"""
FlashMind — Gymnasium RL Environment
======================================
Custom OpenAI Gym / Gymnasium environment for training the arbitrage agent.

Observation Space:
    • Pool state vectors (reserves, prices, fees) for each observed pool
    • Strategy summary vector (opportunities found, best PnL per strategy)
    • Market state (gas price, ETH price, block number)
    • Agent state (portfolio balances, cumulative PnL)

Action Space:
    • Discrete: {0=HOLD, 1..N=execute opportunity i}
    • Multi-Discrete: {strategy_choice, trade_size_bucket}
    • Box (continuous): {strategy_weights, capital_allocation}

Reward:
    • Primary: net PnL of executed trade (after gas, fees, slippage)
    • Penalty: gas cost for failed/bad trades
    • Shaping: bonus for correctly identifying profitable opportunities

Episode:
    • T_max = 1024 steps (simulating ~1024 blocks ≈ ~3.4 hours on Ethereum)
    • Market evolves each step (price changes, new imbalances, new opportunities)
    • Episode ends on timeout or if agent runs out of capital
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from src.amm.pools import AMMPool, Market, Token
from src.amm.market_gen import MarketGenerator
from src.strategies.engines import (
    Opportunity, StrategyRegistry,
)
from src.strategies.cutting_edge import create_full_registry, ALL_STRATEGY_NAMES, NUM_STRATEGIES


# ---------------------------------------------------------------------------
# Environment Constants
# ---------------------------------------------------------------------------

MAX_POOLS_OBSERVED = 50          # Max pools in observation (padding if fewer)
MAX_OPPORTUNITIES = 20          # Max opportunities presented per step
OPPORTUNITY_FEATURES = 11       # Features per opportunity vector
STRATEGY_FEATURES = NUM_STRATEGIES * 3  # 21 strategies x 3 features = 63
POOL_FEATURES = 6               # Features per pool vector
AGENT_FEATURES = 10             # Agent state features
MARKET_FEATURES = 5             # Market-level features
T_MAX = 1024                   # Max steps per episode
INITIAL_CAPITAL_ETH = 10.0     # Starting capital in ETH


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

try:
    import gymnasium as gym
    from gymnasium import spaces
    _BaseEnv = gym.Env
except ImportError:
    import gym
    from gym import spaces
    _BaseEnv = gym.Env


class FlashLoanArbEnv(_BaseEnv):
    """
    Gymnasium-compatible environment for flash loan arbitrage RL training.

    Supports multiple action space modes:
        - "discrete": single action = choose opportunity index or hold
        - "multi_discrete": (strategy, size_bucket) pair
        - "continuous": continuous strategy weights + capital allocation
    """

    metadata = {"render_modes": ["human", "ansi"]}

    def __init__(
        self,
        action_mode: str = "discrete",
        num_pools: int = 30,
        seed: Optional[int] = None,
        gas_price_range: Tuple[float, float] = (10.0, 100.0),
        eth_price_range: Tuple[float, float] = (1500.0, 4500.0),
        price_volatility: float = 0.005,
        imbalance_probability: float = 0.15,
        max_steps: int = T_MAX,
        initial_capital: float = INITIAL_CAPITAL_ETH,
        render_mode: Optional[str] = None,
        scan_frequency: int = 5,  # scan strategies every N steps
    ):
        """
        Args:
            action_mode: "discrete", "multi_discrete", or "continuous"
            num_pools: Number of pools to generate per episode
            seed: Random seed
            gas_price_range: (min, max) gas price in Gwei
            eth_price_range: (min, max) ETH price in USD
            price_volatility: Per-step price change volatility
            imbalance_probability: Probability of new imbalance per step
            max_steps: Episode length
            initial_capital: Starting capital in ETH
            render_mode: "human" or "ansi"
        """
        self.action_mode = action_mode
        self.num_pools = num_pools
        self.seed = seed
        self.gas_price_range = gas_price_range
        self.eth_price_range = eth_price_range
        self.price_volatility = price_volatility
        self.imbalance_probability = imbalance_probability
        self.max_steps = max_steps
        self.initial_capital = initial_capital
        self.render_mode = render_mode

        # Internal state
        self.rng: Optional[np.random.Generator] = None
        self.market: Optional[Market] = None
        self.registry: Optional[StrategyRegistry] = None
        self.current_opportunities: List[Opportunity] = []
        self.step_count: int = 0
        self.cumulative_pnl: float = 0.0
        self.capital: float = initial_capital
        self.trade_history: List[Dict] = []
        self.gas_price_gwei: float = 30.0
        self.eth_price_usd: float = 2500.0
        self.scan_frequency: int = scan_frequency

        # Build spaces
        self._build_spaces()

    def _build_spaces(self):
        """Build observation and action spaces based on mode."""
        # Observation space
        obs_size = self._observation_size()
        self.observation_space = spaces.Box(
            low=-1e10, high=1e10, shape=(obs_size,), dtype=np.float32
        )

        # Action space
        if self.action_mode == "discrete":
            # 0 = hold, 1..MAX_OPPORTUNITIES = execute opportunity i
            self.action_space = spaces.Discrete(MAX_OPPORTUNITIES + 1)

        elif self.action_mode == "multi_discrete":
            # (strategy: 0=hold + 21 strategies, size_bucket: 0-4)
            self.action_space = spaces.MultiDiscrete([NUM_STRATEGIES + 1, 5])

        elif self.action_mode == "continuous":
            # [strategy_weights(21), capital_fraction(1)]
            self.action_space = spaces.Box(
                low=0.0, high=1.0, shape=(NUM_STRATEGIES + 1,), dtype=np.float32
            )
        else:
            raise ValueError(f"Unknown action mode: {self.action_mode}")

    def _observation_size(self) -> int:
        """Calculate total observation vector size."""
        return (
            MAX_POOLS_OBSERVED * POOL_FEATURES    # Pool states
            + MAX_OPPORTUNITIES * OPPORTUNITY_FEATURES  # Opportunity features
            + STRATEGY_FEATURES                   # Strategy summary
            + AGENT_FEATURES                       # Agent state
            + MARKET_FEATURES                      # Market state
        )

    # ------------------------------------------------------------------
    # Gymnasium API
    # ------------------------------------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
        options: Optional[Dict] = None,
    ) -> Tuple[np.ndarray, Dict]:
        """Reset the environment for a new episode."""
        if seed is not None:
            self.seed = seed

        self.rng = np.random.default_rng(self.seed)

        # Generate fresh market
        gen = MarketGenerator(
            seed=self.seed,
            num_extra_tokens=8,
            volatility=self.price_volatility,
        )
        self.market = gen.generate_market(num_pools=self.num_pools)

        # Strategy registry with all 21 strategies
        self.gas_price_gwei = float(self.rng.uniform(*self.gas_price_range))
        self.eth_price_usd = float(self.rng.uniform(*self.eth_price_range))
        self.registry = create_full_registry(
            gas_price_gwei=self.gas_price_gwei,
            eth_price_usd=self.eth_price_usd,
        )

        # Reset agent state
        self.step_count = 0
        self.cumulative_pnl = 0.0
        self.capital = self.initial_capital
        self.trade_history = []

        # Initial scan
        self._scan_counter = 0
        self._cached_static_results = None
        self._scan_cached_opportunities()

        obs = self._build_observation()
        info = self._build_info()
        return obs, info

    def step(
        self, action: Any
    ) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """
        Execute one environment step.

        Args:
            action: Agent's action (depends on action_mode)

        Returns:
            obs, reward, terminated, truncated, info
        """
        self.step_count += 1
        reward = 0.0
        executed = False

        # Parse action and execute
        opp_executed = self._parse_and_execute(action)

        if opp_executed is not None:
            executed = True
            # Apply the trade — convert PnL to ETH equivalent
            net_pnl_raw = opp_executed.net_profit
            net_pnl_eth = self._to_eth(net_pnl_raw, opp_executed.profit_token)
            # Cap PnL to prevent capital explosion during training
            net_pnl_eth = max(-1.0, min(10.0, net_pnl_eth))
            self.capital += net_pnl_eth
            self.cumulative_pnl += net_pnl_eth

            # Reward = net PnL in ETH (clipped for training stability)
            # Raw profits can be very large in simulation; clip to reasonable range
            reward = max(-1.0, min(10.0, net_pnl_eth))

            # Record trade
            self.trade_history.append({
                "step": self.step_count,
                "strategy": opp_executed.strategy_name,
                "gross_profit": net_pnl_eth,
                "net_profit": net_pnl_eth,
                "gas_cost": opp_executed.gas_cost / self.eth_price_usd if opp_executed.profit_token.symbol not in ("WETH", "ETH") else opp_executed.gas_cost,
                "capital_used": opp_executed.capital_required,
                "roi": opp_executed.roi,
            })

            # Update pool reserves (simulate the swap impact)
            self._apply_trade_to_market(opp_executed)

        else:
            # Small negative reward for "doing nothing" to encourage action
            # (but not too harsh — holding is sometimes optimal)
            reward = -0.0001

        # Evolve market
        self._evolve_market()

        # Re-scan for new opportunities (every step is expensive;
        # for training speed, scan every few steps)
        self._scan_counter = getattr(self, '_scan_counter', 0) + 1
        if self._scan_counter % self.scan_frequency == 0 or executed:
            self._scan_cached_opportunities()

        # Check termination
        terminated = False
        truncated = self.step_count >= self.max_steps

        if self.capital <= 0.01:  # Agent ran out of capital
            terminated = True

        obs = self._build_observation()
        info = self._build_info()

        return obs, reward, terminated, truncated, info

    def render(self):
        """Render the current state."""
        if self.render_mode == "human":
            print(f"\n{'='*60}")
            print(f"Step {self.step_count}/{self.max_steps}")
            print(f"Capital: {self.capital:.6f} ETH")
            print(f"Cumulative PnL: {self.cumulative_pnl:.6f} ETH")
            print(f"Gas: {self.gas_price_gwei:.1f} Gwei | ETH: ${self.eth_price_usd:.0f}")
            print(f"Opportunities: {len(self.current_opportunities)}")
            for i, opp in enumerate(self.current_opportunities[:5]):
                print(f"  [{i}] {opp.strategy_name}: net={opp.net_profit:.6f} roi={opp.roi:.4f}")
            print(f"{'='*60}\n")

    def close(self):
        """Clean up."""
        self.market = None
        self.registry = None
        self.current_opportunities = []

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _scan_opportunities(self):
        """Run all strategies and collect opportunities."""
        if self.registry and self.market:
            results = self.registry.scan_all(self.market)
            self.current_opportunities = self.registry.get_all_opportunities(
                results, market=self.market
            )[:MAX_OPPORTUNITIES]

    def _scan_cached_opportunities(self):
        """
        Scan with caching: AMM-dependent strategies re-scan every call,
        but AMM-independent strategies (lending_rate, vault_nav, liquid_staking,
        intent_arb, cross_chain, funding_rate) are cached and refreshed
        only once per episode or when their data changes.
        """
        if self.registry and self.market:
            # AMM-dependent strategies (need fresh pool data)
            amm_strategies = [
                "cross_dex", "triangular", "flash_loan",
                "liquidation", "sandwich", "jit_liquidity", "mev_bundle",
                "dex_aggregator", "lp_rebalance", "stablecoin_depeg",
            ]
            # AMM-independent (cached — data comes from external sources)
            cached_strategies = [
                "funding_rate", "lending_rate", "intent_arb",
                "vault_nav", "liquid_staking", "cross_chain",
                "oracle_delay", "restaking_yield", "options_premium",
                "memecoin_snipe", "vetoken_bribe",
            ]

            results = {}
            for name, strategy in self.registry.strategies.items():
                if name in amm_strategies:
                    try:
                        results[name] = strategy.scan(self.market)
                    except Exception:
                        results[name] = []
                elif not hasattr(self, '_cached_static_results'):
                    # First scan of static strategies
                    try:
                        results[name] = strategy.scan(self.market)
                    except Exception:
                        results[name] = []

            if self._cached_static_results is None:
                self._cached_static_results = {
                    k: v for k, v in results.items()
                    if k in cached_strategies
                }

            # Merge cached results
            if self._cached_static_results:
                for k in cached_strategies:
                    if k not in results:
                        results[k] = self._cached_static_results.get(k, [])

            self.current_opportunities = self.registry.get_all_opportunities(
                results, market=self.market
            )[:MAX_OPPORTUNITIES]

    def _parse_and_execute(self, action: Any) -> Optional[Opportunity]:
        """Parse the agent's action and return the chosen opportunity."""
        if self.action_mode == "discrete":
            if action == 0:
                return None  # HOLD
            idx = action - 1
            if 0 <= idx < len(self.current_opportunities):
                opp = self.current_opportunities[idx]
                # Check capital constraint
                if not opp.uses_flash_loan and opp.capital_required > self.capital:
                    return None  # Can't afford it
                return opp
            return None

        elif self.action_mode == "multi_discrete":
            strategy_idx, size_bucket = action
            if strategy_idx == 0:
                return None  # HOLD

            # Map strategy index to opportunities
            if strategy_idx - 1 >= len(ALL_STRATEGY_NAMES):
                return None

            target_strategy = ALL_STRATEGY_NAMES[strategy_idx - 1]
            for opp in self.current_opportunities:
                if opp.strategy_name == target_strategy:
                    size_factor = [0.2, 0.5, 1.0, 2.0, 5.0][size_bucket]
                    if not opp.uses_flash_loan:
                        required = opp.capital_required * size_factor
                        if required > self.capital:
                            continue
                    return opp
            return None

        elif self.action_mode == "continuous":
            weights = action[:NUM_STRATEGIES]
            capital_frac = action[NUM_STRATEGIES]

            # Weighted selection: pick best opportunity by weighted score
            if len(self.current_opportunities) == 0:
                return None

            best_score = -float("inf")
            best_opp = None

            for opp in self.current_opportunities:
                try:
                    s_idx = ALL_STRATEGY_NAMES.index(opp.strategy_name)
                    weight = weights[s_idx]
                except ValueError:
                    weight = 0.0

                score = weight * opp.net_profit * capital_frac
                if score > best_score:
                    best_score = score
                    best_opp = opp

            if best_opp and best_score > 0:
                return best_opp
            return None

        return None

    def _to_eth(self, amount: float, token: Token) -> float:
        """Convert an amount from token units to ETH equivalent."""
        if token.symbol in ("WETH", "ETH"):
            return amount
        elif token.symbol in ("USDT", "USDC", "DAI", "FRAX", "LUSD",
                             "BUSD", "TUSD", "USDP", "USDe"):
            return amount / self.eth_price_usd
        else:
            # Approximate: use ratio of token to ETH
            return amount / self.eth_price_usd * 0.1  # rough scaling

    def _apply_trade_to_market(self, opp: Opportunity):
        """Update pool reserves after a trade is executed."""
        for step in opp.path:
            pool = step.pool
            try:
                if hasattr(pool, 'set_reserves'):
                    # V2 pool
                    res = pool.reserves
                    token_in_sym = step.token_in.symbol
                    token_out_sym = step.token_out.symbol

                    if pool.token0.symbol == token_in_sym:
                        new_r0 = res[pool.token0.symbol] + step.amount_in
                        new_r1 = res[pool.token1.symbol] - step.expected_amount_out
                    else:
                        new_r0 = res[pool.token0.symbol] - step.expected_amount_out
                        new_r1 = res[pool.token1.symbol] + step.amount_in

                    pool.set_reserves(
                        max(0.001, new_r0),
                        max(0.001, new_r1),
                    )
            except Exception:
                pass  # Non-critical — simulation continues

    def _evolve_market(self):
        """
        Evolve the market state between steps.

        Simulates:
        - Small random price movements (natural trading)
        - New imbalances (arb opportunities appearing)
        - Gas price changes
        - ETH price changes
        """
        if self.rng is None:
            return

        # Update gas and ETH prices (mean-reverting random walk)
        self.gas_price_gwei += self.rng.normal(0, 2.0)
        self.gas_price_gwei = np.clip(
            self.gas_price_gwei, *self.gas_price_range
        )

        self.eth_price_usd += self.rng.normal(0, self.eth_price_usd * 0.001)
        self.eth_price_usd = np.clip(
            self.eth_price_usd, *self.eth_price_range
        )

        # Update pool reserves (simulate external trades)
        for pool in self.market.pools.values():
            if self.rng.random() < 0.3:
                self._jitter_pool(pool)

        # Occasionally create new imbalances
        if self.rng.random() < self.imbalance_probability:
            # Pick a random pool and create an imbalance
            pools = list(self.market.pools.values())
            if pools:
                target = pools[self.rng.integers(len(pools))]
                self._create_imbalance(target)

    def _jitter_pool(self, pool: AMMPool, magnitude: float = 0.002):
        """Apply small random changes to pool reserves."""
        if hasattr(pool, 'set_reserves'):
            res = pool.reserves
            r0_sym = pool.token0.symbol
            r1_sym = pool.token1.symbol
            r0 = res[r0_sym]
            r1 = res[r1_sym]

            # Small shift (simulates external trades)
            factor = 1.0 + self.rng.normal(0, magnitude)
            if self.rng.random() > 0.5:
                r0 *= factor
            else:
                r1 *= factor

            pool.set_reserves(max(0.001, r0), max(0.001, r1))

    def _create_imbalance(self, pool: AMMPool):
        """Create a larger imbalance in a specific pool."""
        if hasattr(pool, 'set_reserves'):
            res = pool.reserves
            r0_sym = pool.token0.symbol
            r1_sym = pool.token1.symbol
            r0 = res[r0_sym]
            r1 = res[r1_sym]

            # Larger shift (simulates a big trade or oracle lag)
            factor = self.rng.uniform(0.85, 1.15)
            if self.rng.random() > 0.5:
                r0 *= factor
                r1 /= factor
            else:
                r0 /= factor
                r1 *= factor

            pool.set_reserves(max(0.001, r0), max(0.001, r1))

    # ------------------------------------------------------------------
    # Observation Builder
    # ------------------------------------------------------------------

    def _build_observation(self) -> np.ndarray:
        """Build the full observation vector for the agent."""
        vec = np.zeros(self._observation_size(), dtype=np.float32)
        idx = 0

        # 1. Pool state vectors
        pools = list(self.market.pools.values())[:MAX_POOLS_OBSERVED]
        for i in range(MAX_POOLS_OBSERVED):
            if i < len(pools):
                pool = pools[i]
                res = pool.reserves
                reserves = list(res.values())

                # Normalised features per pool
                vec[idx + 0] = math.log10(reserves[0] + 1)  # log reserve 0
                vec[idx + 1] = math.log10(reserves[1] + 1)  # log reserve 1
                try:
                    price = pool.spot_price(pool.token0, pool.token1)
                    vec[idx + 2] = math.log10(max(price, 1e-10))
                except (ZeroDivisionError, ValueError):
                    vec[idx + 2] = 0.0
                vec[idx + 3] = pool.fee_bps / 1000.0  # fee (normalised)
                vec[idx + 4] = sum(reserves)  # total liquidity
                vec[idx + 5] = hash(pool.protocol) % 100 / 100.0  # protocol id
            idx += POOL_FEATURES

        # 2. Opportunity vectors
        for i in range(MAX_OPPORTUNITIES):
            if i < len(self.current_opportunities):
                opp_vec = self.current_opportunities[i].to_observation_vector()
                for j, v in enumerate(opp_vec):
                    if j < OPPORTUNITY_FEATURES:
                        vec[idx + j] = v
            idx += OPPORTUNITY_FEATURES

        # 3. Strategy summary vector (use cached scan results)
        if self.registry and hasattr(self, '_cached_static_results'):
            # Build summary from already-scanned opportunities
            summary = np.zeros(STRATEGY_FEATURES, dtype=np.float32)
            ALL_NAMES = ALL_STRATEGY_NAMES
            opps_by_strategy = {}
            for opp in self.current_opportunities:
                if opp.strategy_name not in opps_by_strategy:
                    opps_by_strategy[opp.strategy_name] = []
                opps_by_strategy[opp.strategy_name].append(opp)

            for si, name in enumerate(ALL_NAMES):
                opps = opps_by_strategy.get(name, [])
                summary[si * 3 + 0] = len(opps)
                summary[si * 3 + 1] = max((o.net_profit for o in opps), default=0.0)
                summary[si * 3 + 2] = max((o.roi for o in opps), default=0.0)
            for i, v in enumerate(summary):
                vec[idx + i] = v
        idx += STRATEGY_FEATURES

        # 4. Agent state features
        vec[idx + 0] = self.capital
        vec[idx + 1] = self.initial_capital
        vec[idx + 2] = self.cumulative_pnl
        vec[idx + 3] = self.cumulative_pnl / max(self.initial_capital, 0.001)
        vec[idx + 4] = len(self.trade_history)
        vec[idx + 5] = len(self.current_opportunities)
        winning_trades = sum(1 for t in self.trade_history if t["net_profit"] > 0)
        vec[idx + 6] = winning_trades
        total_trades = len(self.trade_history) or 1
        vec[idx + 7] = winning_trades / total_trades  # win rate
        vec[idx + 8] = self.step_count / self.max_steps  # progress
        vec[idx + 9] = self.capital / self.initial_capital  # capital ratio
        idx += AGENT_FEATURES

        # 5. Market features
        vec[idx + 0] = self.gas_price_gwei / 100.0
        vec[idx + 1] = self.eth_price_usd / 10000.0
        vec[idx + 2] = self.price_volatility
        vec[idx + 3] = self.imbalance_probability
        vec[idx + 4] = len(self.market.pools)
        # idx += MARKET_FEATURES  # not needed after this

        return vec

    def _build_info(self) -> Dict:
        """Build the info dict returned with each step."""
        return {
            "step": self.step_count,
            "capital": self.capital,
            "cumulative_pnl": self.cumulative_pnl,
            "num_opportunities": len(self.current_opportunities),
            "num_trades": len(self.trade_history),
            "win_rate": (
                sum(1 for t in self.trade_history if t["net_profit"] > 0)
                / max(len(self.trade_history), 1)
            ),
            "gas_price_gwei": self.gas_price_gwei,
            "eth_price_usd": self.eth_price_usd,
            "opportunities": [
                {
                    "strategy": o.strategy_name,
                    "net_profit": o.net_profit,
                    "roi": o.roi,
                    "capital_required": o.capital_required,
                    "gas_cost": o.gas_cost,
                    "uses_flash_loan": o.uses_flash_loan,
                }
                for o in self.current_opportunities[:5]
            ],
        }
