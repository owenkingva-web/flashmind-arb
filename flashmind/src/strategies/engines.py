"""
FlashMind — Arbitrage Strategy Engines
========================================
Every strategy the RL agent can choose from.

Each strategy:
    • scan(market) → List[Opportunity]
        Scans the market for opportunities.
    • Opportunity has:  expected_pnl, gas_cost, net_pnl, action_plan
    • The agent's action selects which opportunity to execute.

Strategies implemented:
    1. CrossDexArbitrage      — buy low / sell high across two DEX pools
    2. TriangularArbitrage     — A → B → C → A through 3+ pools
    3. FlashLoanArbitrage      — borrow flash loan → arb → repay
    4. LiquidationHunter       — liquidate undercollateralized CDPs
    5. SandwichAttack          — front-run + back-run a victim swap
    6. FundingRateArbitrage    — perp funding rate vs spot hedge
    7. MEVBundleComposer       — combine multiple opportunities atomically
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.amm.pools import AMMPool, Market, Token
from src.amm.constants import (
    FLASH_LOAN_GAS_OVERHEAD, GWEI, SWAP_GAS_BASE,
    MIN_PROFIT_WEI_THRESHOLD, FLASH_LOAN_FEE_BPS,
)


# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------

@dataclass
class SwapStep:
    """A single swap within a multi-step arbitrage path."""
    pool: AMMPool
    token_in: Token
    token_out: Token
    amount_in: float
    expected_amount_out: float

    @property
    def address(self) -> str:
        return self.pool.address


@dataclass
class Opportunity:
    """
    A detected arbitrage opportunity with full PnL breakdown.

    The RL agent observes a vector of Opportunity objects and selects
    which one(s) to execute.
    """
    strategy_name: str
    path: List[SwapStep]
    profit_token: Token

    # Financials (in profit_token units)
    gross_profit: float = 0.0      # before fees + gas
    total_fees: float = 0.0       # pool swap fees
    gas_cost: float = 0.0         # in ETH (converted to profit_token)
    flash_loan_fee: float = 0.0   # if flash loan used
    net_profit: float = 0.0       # gross_profit - total_fees - gas_cost - flash_loan_fee

    # Execution metadata
    capital_required: float = 0.0  # upfront capital needed
    uses_flash_loan: bool = False
    gas_estimate: int = 0          # gas units
    confidence: float = 1.0       # 0–1, model confidence in the opportunity
    risk_score: float = 0.0       # 0–1, higher = riskier ( MEV competition, slippage)

    # Metadata for RL observation
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.net_profit = (
            self.gross_profit
            - self.total_fees
            - self.gas_cost
            - self.flash_loan_fee
        )

    @property
    def is_profitable(self) -> bool:
        return self.net_profit > MIN_PROFIT_WEI_THRESHOLD

    @property
    def roi(self) -> float:
        if self.capital_required <= 0:
            return 0.0
        return self.net_profit / self.capital_required

    def to_observation_vector(self) -> List[float]:
        """Convert to a flat float vector for RL observation space."""
        return [
            self.gross_profit,
            self.total_fees,
            self.gas_cost,
            self.flash_loan_fee,
            self.net_profit,
            self.roi,
            self.capital_required,
            float(self.uses_flash_loan),
            self.confidence,
            self.risk_score,
            len(self.path),
        ]


# ---------------------------------------------------------------------------
# Abstract base strategy
# ---------------------------------------------------------------------------

class Strategy(ABC):
    """Base class all strategies extend."""

    def __init__(
        self,
        gas_price_gwei: float = 30.0,
        eth_price_usd: float = 2000.0,
        max_slippage_bps: int = 50,
        min_profit: float = MIN_PROFIT_WEI_THRESHOLD,
    ):
        self.gas_price_gwei = gas_price_gwei
        self.eth_price_usd = eth_price_usd
        self.gas_price_eth = gas_price_gwei * GWEI  # in ETH-wei
        self.max_slippage_bps = max_slippage_bps
        self.min_profit = min_profit

    @abstractmethod
    def scan(self, market: Market) -> List[Opportunity]:
        """Scan the market and return all viable opportunities."""
        ...

    def _estimate_gas_cost(self, gas_units: int, profit_token: Token) -> float:
        """Convert gas cost to profit_token units (matching pool reserve scale)."""
        # cost_eth = gas_units * gwei * 1e-9 (in ETH, not wei)
        cost_eth = gas_units * self.gas_price_gwei * 1e-9
        # Convert to profit_token units
        if profit_token.symbol in ("WETH", "ETH"):
            return cost_eth
        elif profit_token.symbol in ("USDT", "USDC", "DAI", "FRAX", "LUSD",
                                     "BUSD", "TUSD", "USDP", "USDe"):
            return cost_eth * self.eth_price_usd
        else:
            # Approximate using ETH price
            return cost_eth * self.eth_price_usd / 1000.0

    def _compute_swap_gas(self, num_swaps: int) -> int:
        """Gas for N swaps + overhead."""
        return num_swaps * SWAP_GAS_BASE

    def _price_token_in_eth(self, token: Token, market: Market) -> float:
        """Get approximate token price in ETH."""
        if token.symbol in ("WETH", "ETH"):
            return 1.0
        # Look for a WETH pair
        for pool in market.pools.values():
            symbols = {t.symbol for t in pool.tokens}
            if "WETH" in symbols and token.symbol in symbols:
                try:
                    weth_token = [t for t in pool.tokens if t.symbol == "WETH"][0]
                    return pool.spot_price(weth_token, token)
                except (ZeroDivisionError, IndexError):
                    continue
        return 0.0


# ===========================================================================
# Strategy 1: Cross-DEX Arbitrage
# ===========================================================================

class CrossDexArbitrage(Strategy):
    """
    Buy token X on DEX A (cheaper) and sell on DEX B (more expensive)
    for the same pair.

    This is the simplest and most common arb. The agent learns to find
    the best pair of pools and the optimal trade size.
    """

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        pairs = market.get_all_pairs()
        for token_a_sym, token_b_sym in pairs:
            pools = market.get_pools_by_pair(token_a_sym, token_b_sym)
            if len(pools) < 2:
                continue

            token_a = market.token_registry[token_a_sym]
            token_b = market.token_registry[token_b_sym]

            # Compare every pair of pools
            for i in range(len(pools)):
                for j in range(i + 1, len(pools)):
                    opp = self._evaluate_pair(pools[i], pools[j], token_a, token_b)
                    if opp:
                        opportunities.append(opp)

        return opportunities

    def _evaluate_pair(
        self,
        pool_a: AMMPool,
        pool_b: AMMPool,
        token_a: Token,
        token_b: Token,
    ) -> Optional[Opportunity]:
        """Evaluate arbitrage between two pools for the same pair."""

        # Find the direction with the price discrepancy
        price_a = pool_a.spot_price(token_a, token_b)
        price_b = pool_b.spot_price(token_a, token_b)

        if abs(price_a - price_b) / max(price_a, price_b) < 0.001:
            return None  # < 0.1% difference, not worth it

        # Determine direction: buy on cheaper pool, sell on expensive
        if price_a < price_b:
            buy_pool, sell_pool = pool_a, pool_b
        else:
            buy_pool, sell_pool = pool_b, pool_a

        # Try multiple trade sizes to find optimal (binary search)
        best_opp = None
        best_pnl = 0.0

        # Reserve-based size estimation
        buy_reserves = buy_pool.reserves
        reserve_values = list(buy_reserves.values())
        max_size = min(reserve_values) * 0.05  # max 5% of pool

        for fraction in [0.001, 0.005, 0.01, 0.02, 0.05]:
            amount = max_size * fraction
            opp = self._simulate_trade(
                buy_pool, sell_pool, token_a, token_b, amount
            )
            if opp and opp.net_profit > best_pnl:
                best_pnl = opp.net_profit
                best_opp = opp

        return best_opp

    def _simulate_trade(
        self,
        buy_pool: AMMPool,
        sell_pool: AMMPool,
        token_a: Token,
        token_b: Token,
        amount_in: float,
    ) -> Optional[Opportunity]:
        """Simulate: buy token_b on buy_pool with amount_in of token_a, sell on sell_pool."""

        # Buy step: token_a → token_b on buy_pool
        amount_b, fee_buy = buy_pool.swap(token_a, amount_in, token_b)

        # Sell step: token_b → token_a on sell_pool
        amount_a_out, fee_sell = sell_pool.swap(token_b, amount_b, token_a)

        gross_profit = amount_a_out - amount_in
        if gross_profit <= 0:
            return None

        gas_units = self._compute_swap_gas(2)
        gas_cost = self._estimate_gas_cost(gas_units, token_a)
        total_fees = fee_buy + fee_sell

        return Opportunity(
            strategy_name="cross_dex",
            path=[
                SwapStep(buy_pool, token_a, token_b, amount_in, amount_b),
                SwapStep(sell_pool, token_b, token_a, amount_b, amount_a_out),
            ],
            profit_token=token_a,
            gross_profit=gross_profit,
            total_fees=total_fees,
            gas_cost=gas_cost,
            net_profit=gross_profit - total_fees - gas_cost,
            capital_required=amount_in,
            gas_estimate=gas_units,
            confidence=self._estimate_confidence(gross_profit, total_fees),
            risk_score=self._estimate_risk(buy_pool, sell_pool),
        )

    def _estimate_confidence(self, profit: float, fees: float) -> float:
        """Higher profit/fee ratio = higher confidence."""
        if fees <= 0:
            return 1.0
        ratio = profit / fees
        return min(1.0, ratio / 10.0)

    def _estimate_risk(self, pool_a: AMMPool, pool_b: AMMPool) -> float:
        """Estimate MEV competition risk based on pool liquidity."""
        # Lower liquidity = higher risk of being front-run
        r_a = list(pool_a.reserves.values())
        r_b = list(pool_b.reserves.values())
        avg_liq = (min(r_a) + min(r_b)) / 2
        # Higher liquidity = lower risk (0.1 to 0.9)
        return max(0.1, min(0.9, 1.0 - math.log10(avg_liq + 1) / 12.0))


# ===========================================================================
# Strategy 2: Triangular Arbitrage
# ===========================================================================

class TriangularArbitrage(Strategy):
    """
    Three-hop arbitrage:  A → B → C → A

    E.g., WETH → USDC → WBTC → WETH

    Profitable when the product of the three exchange rates ≠ 1.
    The RL agent learns to find the best triangle and optimal size.
    """

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []
        tokens = list(market.token_registry.values())

        # Find all possible triangles
        triangles = self._find_triangles(market, tokens)

        for (token_a, token_b, token_c, pool_ab, pool_bc, pool_ca) in triangles:
            opp = self._evaluate_triangle(
                market, token_a, token_b, token_c,
                pool_ab, pool_bc, pool_ca
            )
            if opp:
                opportunities.append(opp)

        return opportunities

    def _find_triangles(
        self, market: Market, tokens: List[Token]
    ) -> List[Tuple[Token, Token, Token, AMMPool, AMMPool, AMMPool]]:
        """Find all valid 3-hop triangular paths."""
        triangles = []
        for token_a in tokens[:10]:  # Limit search space
            pools_from_a = market.get_pools_by_pair(token_a.symbol, "?")
            # Get all tokens connected to token_a
            connected_b = set()
            for pool in market.pools.values():
                symbols = {t.symbol for t in pool.tokens}
                if token_a.symbol in symbols:
                    for t in pool.tokens:
                        if t.symbol != token_a.symbol:
                            connected_b.add(t)

            for token_b_sym in connected_b:
                token_b = market.token_registry.get(token_b_sym)
                if not token_b:
                    continue

                # Find pools: A→B
                pools_ab = market.get_pools_by_pair(token_a.symbol, token_b.symbol)

                # Find tokens connected to B (excluding A)
                connected_c = set()
                for pool in market.pools.values():
                    symbols = {t.symbol for t in pool.tokens}
                    if token_b.symbol in symbols:
                        for t in pool.tokens:
                            if t.symbol not in (token_a.symbol, token_b.symbol):
                                connected_c.add(t)

                for token_c_sym in connected_c:
                    token_c = market.token_registry.get(token_c_sym)
                    if not token_c:
                        continue

                    pools_bc = market.get_pools_by_pair(token_b.symbol, token_c.symbol)
                    pools_ca = market.get_pools_by_pair(token_c.symbol, token_a.symbol)

                    if not pools_ab or not pools_bc or not pools_ca:
                        continue

                    # Best pools for each leg (highest liquidity)
                    pool_ab = max(pools_ab, key=lambda p: min(p.reserves.values()))
                    pool_bc = max(pools_bc, key=lambda p: min(p.reserves.values()))
                    pool_ca = max(pools_ca, key=lambda p: min(p.reserves.values()))

                    triangles.append((
                        token_a, token_b, token_c,
                        pool_ab, pool_bc, pool_ca
                    ))

        return triangles

    def _evaluate_triangle(
        self,
        market: Market,
        token_a: Token,
        token_b: Token,
        token_c: Token,
        pool_ab: AMMPool,
        pool_bc: AMMPool,
        pool_ca: AMMPool,
    ) -> Optional[Opportunity]:
        """Evaluate a single triangular path: A → B → C → A."""

        best_opp = None
        best_pnl = 0.0

        # Size estimation
        reserves = list(pool_ab.reserves.values())
        max_size = min(reserves) * 0.02  # conservative

        for fraction in [0.001, 0.005, 0.01, 0.02]:
            amount_start = max_size * fraction

            try:
                # Hop 1: A → B
                amount_b, fee1 = pool_ab.swap(token_a, amount_start, token_b)
                # Hop 2: B → C
                amount_c, fee2 = pool_bc.swap(token_b, amount_b, token_c)
                # Hop 3: C → A
                amount_a_final, fee3 = pool_ca.swap(token_c, amount_c, token_a)
            except (ValueError, ZeroDivisionError):
                continue

            gross_profit = amount_a_final - amount_start
            if gross_profit <= 0:
                continue

            gas_units = self._compute_swap_gas(3) + 20_000  # approval overhead
            gas_cost = self._estimate_gas_cost(gas_units, token_a)
            total_fees = fee1 + fee2 + fee3

            opp = Opportunity(
                strategy_name="triangular",
                path=[
                    SwapStep(pool_ab, token_a, token_b, amount_start, amount_b),
                    SwapStep(pool_bc, token_b, token_c, amount_b, amount_c),
                    SwapStep(pool_ca, token_c, token_a, amount_c, amount_a_final),
                ],
                profit_token=token_a,
                gross_profit=gross_profit,
                total_fees=total_fees,
                gas_cost=gas_cost,
                net_profit=gross_profit - total_fees - gas_cost,
                capital_required=amount_start,
                gas_estimate=gas_units,
                metadata={"triangle": f"{token_a.symbol}→{token_b.symbol}→{token_c.symbol}→{token_a.symbol}"},
            )

            if opp.net_profit > best_pnl:
                best_pnl = opp.net_profit
                best_opp = opp

        return best_opp


# ===========================================================================
# Strategy 3: Flash Loan Arbitrage
# ===========================================================================

class FlashLoanArbitrage(Strategy):
    """
    Borrow a flash loan, execute an arbitrage, repay in the same tx.

    The advantage: no upfront capital required. The RL agent learns when
    the profit after flash loan fees + gas exceeds the loan cost.

    Supports: Aave V3, dYdX, Balancer, Uniswap flash swaps.
    """

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        # Flash loan providers (in simulation, any pool can be a provider)
        providers = {
            "aave_v3": FLASH_LOAN_FEE_BPS.get("aave_v3", 5),
            "dydx_v3": FLASH_LOAN_FEE_BPS.get("dydx_v3", 0),
            "balancer_v2": FLASH_LOAN_FEE_BPS.get(BALANCER_V2_POOL := "balancer_v2", 0),
        }

        # Get all pools that could be arb targets
        all_pools = list(market.pools.values())

        for provider_name, fee_bps in providers.items():
            for token in market.token_registry.values():
                # Try each token as the loan asset
                opp = self._evaluate_flash_loan(
                    market, provider_name, fee_bps, token, all_pools
                )
                if opp:
                    opportunities.append(opp)

        return opportunities

    def _evaluate_flash_loan(
        self,
        market: Market,
        provider: str,
        fee_bps: int,
        loan_token: Token,
        pools: List[AMMPool],
    ) -> Optional[Opportunity]:
        """Evaluate a flash loan arb for a specific loan token."""

        best_opp = None
        best_pnl = 0.0

        # Try various loan sizes
        for loan_amount in self._loan_amounts(loan_token, market):
            flash_fee = loan_amount * fee_bps / 10_000

            # Strategy: find best cross-DEX arb using this loan amount
            best_trade_pnl = 0.0
            best_path = None

            pairs = market.get_all_pairs()
            for token_a_sym, token_b_sym in pairs:
                pair_pools = market.get_pools_by_pair(token_a_sym, token_b_sym)
                if len(pair_pools) < 2:
                    continue

                token_a = market.token_registry[token_a_sym]
                token_b = market.token_registry[token_b_sym]

                for i in range(len(pair_pools)):
                    for j in range(i + 1, len(pair_pools)):
                        try:
                            # Buy on pool i, sell on pool j
                            if loan_token.symbol == token_a_sym:
                                amount_b, f1 = pair_pools[i].swap(
                                    token_a, loan_amount, token_b
                                )
                                amount_a_back, f2 = pair_pools[j].swap(
                                    token_b, amount_b, token_a
                                )
                            else:
                                amount_a, f1 = pair_pools[i].swap(
                                    token_b, loan_amount, token_a
                                )
                                amount_b_back, f2 = pair_pools[j].swap(
                                    token_a, amount_a, token_b
                                )
                                amount_a_back = amount_b_back  # profit in loan token

                            trade_pnl = amount_a_back - loan_amount if loan_token.symbol == token_a_sym else amount_b_back - loan_amount

                            if trade_pnl > best_trade_pnl:
                                best_trade_pnl = trade_pnl
                                best_path = (pair_pools[i], pair_pools[j], token_a, token_b)
                        except (ValueError, ZeroDivisionError):
                            continue

            if best_trade_pnl <= 0:
                continue

            gas_units = self._compute_swap_gas(2) + FLASH_LOAN_GAS_OVERHEAD
            gas_cost = self._estimate_gas_cost(gas_units, loan_token)

            opp = Opportunity(
                strategy_name="flash_loan",
                path=[],  # will be filled if we track the actual path
                profit_token=loan_token,
                gross_profit=best_trade_pnl,
                total_fees=0.0,  # swap fees are inside trade_pnl
                gas_cost=gas_cost,
                flash_loan_fee=flash_fee,
                net_profit=best_trade_pnl - flash_fee - gas_cost,
                capital_required=0.0,  # flash loan = no capital!
                uses_flash_loan=True,
                gas_estimate=gas_units,
                metadata={
                    "provider": provider,
                    "loan_amount": loan_amount,
                    "fee_bps": fee_bps,
                },
            )

            if opp.net_profit > best_pnl:
                best_pnl = opp.net_profit
                best_opp = opp

        return best_opp

    def _loan_amounts(self, token: Token, market: Market) -> List[float]:
        """Generate realistic flash loan amounts to test."""
        if token.symbol in ("USDT", "USDC", "DAI"):
            return [100_000, 500_000, 1_000_000, 5_000_000, 10_000_000]
        elif token.symbol == "WETH":
            return [10.0, 50.0, 100.0, 500.0, 1000.0]
        elif token.symbol == "WBTC":
            return [0.5, 1.0, 5.0, 10.0]
        else:
            return [100.0, 1000.0, 10000.0, 100000.0]


BALANCER_V2_POOL = "balancer_v2"  # Avoid undefined reference


# ===========================================================================
# Strategy 4: Liquidation Hunter
# ===========================================================================

@dataclass
class CDPPosition:
    """A collateralized debt position (simplified)."""
    borrower: str
    collateral_token: Token
    collateral_amount: float
    debt_token: Token
    debt_amount: float
    liquidation_threshold: float  # e.g. 0.8 = 80% LTV
    liquidation_bonus: float = 0.05  # 5% bonus for liquidator
    health_factor: float = 1.0  # < 1.0 means liquidatable

    def is_liquidatable(self) -> bool:
        return self.health_factor < 1.0

    @property
    def collateral_ratio(self) -> float:
        if self.debt_amount <= 0:
            return float("inf")
        return self.collateral_amount / self.debt_amount


class LiquidationHunter(Strategy):
    """
    Monitor collateralized positions and liquidate them when
    health factor drops below 1.0.

    Profit = debt_repaid + liquidation_bonus - gas_cost
    """

    def __init__(self, positions: List[CDPPosition] = None, **kwargs):
        super().__init__(**kwargs)
        self.positions = positions or []

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for pos in self.positions:
            if not pos.is_liquidatable():
                continue

            opp = self._evaluate_liquidation(market, pos)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_liquidation(
        self, market: Market, pos: CDPPosition
    ) -> Optional[Opportunity]:
        """Evaluate liquidation of a single CDP position."""

        # Get collateral value in debt token terms
        try:
            price = market.price_between(
                pos.collateral_token.symbol, pos.debt_token.symbol
            )
            if price <= 0:
                return None
        except Exception:
            return None

        collateral_value = pos.collateral_amount * price
        max_debt_to_repay = pos.debt_amount * 0.5  # typically max 50% liquidation

        # Collateral seized (with bonus)
        collateral_seized = max_debt_to_repay / price * (1.0 + pos.liquidation_bonus)

        # Profit = collateral seized - debt repaid (in debt_token terms)
        profit_collateral = collateral_seized - max_debt_to_repay / price

        # Convert to debt token for consistency
        gross_profit = profit_collateral * price

        gas_units = 250_000  # liquidation tx
        gas_cost = self._estimate_gas_cost(gas_units, pos.debt_token)

        return Opportunity(
            strategy_name="liquidation",
            path=[],
            profit_token=pos.debt_token,
            gross_profit=gross_profit,
            total_fees=0.0,
            gas_cost=gas_cost,
            net_profit=gross_profit - gas_cost,
            capital_required=max_debt_to_repay,
            gas_estimate=gas_units,
            confidence=0.95 if pos.health_factor < 0.95 else 0.6,
            risk_score=0.3,  # Liquidation is relatively low-risk
            metadata={
                "borrower": pos.borrower,
                "health_factor": pos.health_factor,
                "collateral_token": pos.collateral_token.symbol,
                "debt_amount": pos.debt_amount,
            },
        )


# ===========================================================================
# Strategy 5: Sandwich Attack
# ===========================================================================

class SandwichAttack(Strategy):
    """
    Detect a pending transaction in the mempool, front-run it (buy before),
    then back-run it (sell after the victim's trade moves the price).

    The RL agent learns:
    - Which pending transactions are profitable to sandwich
    - Optimal front-run amount
    - When NOT to sandwich (competition, risk of failed tx)
    """

    def __init__(self, pending_txs: List[Dict] = None, **kwargs):
        super().__init__(**kwargs)
        self.pending_txs = pending_txs or []

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for tx in self.pending_txs:
            opp = self._evaluate_sandwich(market, tx)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_sandwich(
        self, market: Market, tx: Dict
    ) -> Optional[Opportunity]:
        """
        Evaluate a sandwich opportunity for a pending swap transaction.

        tx should contain:
            - pool: str (address)
            - token_in: str (symbol)
            - token_out: str (symbol)
            - amount_in: float
        """
        pool = market.get_pool(tx.get("pool", ""))
        if not pool:
            return None

        token_in_sym = tx.get("token_in", "")
        token_out_sym = tx.get("token_out", "")
        victim_amount = tx.get("amount_in", 0)

        token_in = market.token_registry.get(token_in_sym)
        token_out = market.token_registry.get(token_out_sym)

        if not token_in or not token_out:
            return None

        if token_in not in pool.tokens or token_out not in pool.tokens:
            return None

        best_opp = None
        best_pnl = 0.0

        # Try different sandwich sizes
        for size_factor in [0.5, 1.0, 2.0, 5.0]:
            front_run_amount = victim_amount * size_factor

            try:
                # Front-run: buy token_out before victim
                fr_amount_out, fr_fee = pool.swap(token_in, front_run_amount, token_out)

                # Victim's trade (moves price in our favour)
                victim_amount_out, _ = pool.swap(token_in, victim_amount, token_out)

                # Back-run: sell token_out after victim moved price
                back_amount_out, back_fee = pool.swap(token_out, fr_amount_out, token_in)

                gross_profit = back_amount_out - front_run_amount
                if gross_profit <= 0:
                    continue

                gas_units = self._compute_swap_gas(2) + 60_000  # 2 extra tx overhead
                gas_cost = self._estimate_gas_cost(gas_units, token_in)
                total_fees = fr_fee + back_fee

                opp = Opportunity(
                    strategy_name="sandwich",
                    path=[
                        SwapStep(pool, token_in, token_out, front_run_amount, fr_amount_out),
                        SwapStep(pool, token_out, token_in, fr_amount_out, back_amount_out),
                    ],
                    profit_token=token_in,
                    gross_profit=gross_profit,
                    total_fees=total_fees,
                    gas_cost=gas_cost,
                    net_profit=gross_profit - total_fees - gas_cost,
                    capital_required=front_run_amount,
                    gas_estimate=gas_units,
                    confidence=0.5,  # Sandwich is uncertain (may get beaten)
                    risk_score=0.7,  # High competition risk
                    metadata={
                        "victim_amount": victim_amount,
                        "front_run_amount": front_run_amount,
                        "pool": pool.address,
                    },
                )

                if opp.net_profit > best_pnl:
                    best_pnl = opp.net_profit
                    best_opp = opp

            except (ValueError, ZeroDivisionError):
                continue

        return best_opp


# ===========================================================================
# Strategy 6: Funding Rate Arbitrage
# ===========================================================================

class FundingRateArbitrage(Strategy):
    """
    Exploit funding rate differences between perpetual DEXes and spot DEXes.

    When perp funding is positive (longs pay shorts):
    - Short perp, long spot → collect funding
    When perp funding is negative:
    - Long perp, short spot → collect funding

    The RL agent learns to:
    - Select the best token + exchange combination
    - Size positions optimally
    - Exit when the spread normalizes
    """

    def __init__(
        self,
        perp_markets: Optional[Dict[str, Dict]] = None,
        **kwargs,
    ):
        """
        Args:
            perp_markets: Dict of {token_symbol: {funding_rate, mark_price, exchange}}
        """
        super().__init__(**kwargs)
        self.perp_markets = perp_markets or self._default_perp_markets()

    def _default_perp_markets(self) -> Dict[str, Dict]:
        """Generate sample perpetual market data."""
        return {
            "WETH": {
                "funding_rate": 0.0001,  # 0.01% per 8h
                "mark_price": 2500.0,
                "exchange": "dYdX",
            },
            "WBTC": {
                "funding_rate": 0.0002,
                "mark_price": 50000.0,
                "exchange": "GMX",
            },
            "ARB": {
                "funding_rate": -0.0003,  # negative = shorts pay longs
                "mark_price": 1.5,
                "exchange": "GMX",
            },
        }

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for token_sym, perp_data in self.perp_markets.items():
            opp = self._evaluate_funding_arb(market, token_sym, perp_data)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_funding_arb(
        self,
        market: Market,
        token_sym: str,
        perp_data: Dict,
    ) -> Optional[Opportunity]:
        """Evaluate funding rate arb for a token."""

        token = market.token_registry.get(token_sym)
        if not token:
            return None

        # Get spot price from AMM pools
        spot_price = 0.0
        for pool in market.pools.values():
            symbols = {t.symbol for t in pool.tokens}
            if "USDC" in symbols and token_sym in symbols:
                try:
                    usdc_token = [t for t in pool.tokens if t.symbol == "USDC"][0]
                    spot_price = pool.spot_price(usdc_token, token)
                    break
                except (ZeroDivisionError, IndexError):
                    continue

        if spot_price <= 0:
            return None

        # Check for price discrepancy
        mark_price = perp_data["mark_price"]
        price_diff_pct = abs(mark_price - spot_price) / spot_price

        if price_diff_pct < 0.002:  # < 0.2% not worth the complexity
            return None

        funding_rate = perp_data["funding_rate"]
        position_size = 100_000.0  # USD notional

        # Funding payment per 8h period
        funding_payment = position_size * abs(funding_rate)

        # Plus PnL from price convergence
        price_convergence_pnl = position_size * price_diff_pct * 0.5  # assume half converges

        gross_profit = funding_payment + price_convergence_pnl

        # Costs
        gas_units = 100_000  # opening + closing positions
        usdc_token = market.token_registry.get("USDC", Token("USDC"))
        gas_cost = self._estimate_gas_cost(gas_units, usdc_token)
        trading_fee = position_size * 0.001  # ~0.1% perp fee
        spot_fee = position_size * 0.003  # 0.3% spot swap fee

        return Opportunity(
            strategy_name="funding_rate",
            path=[],
            profit_token=usdc_token,
            gross_profit=gross_profit,
            total_fees=trading_fee + spot_fee,
            gas_cost=gas_cost,
            net_profit=gross_profit - trading_fee - spot_fee - gas_cost,
            capital_required=position_size,
            gas_estimate=gas_units,
            confidence=min(1.0, price_diff_pct / 0.01),
            risk_score=0.4,  # delta-neutral, relatively low risk
            metadata={
                "token": token_sym,
                "funding_rate": funding_rate,
                "mark_price": mark_price,
                "spot_price": spot_price,
                "price_diff_pct": price_diff_pct,
                "perp_exchange": perp_data["exchange"],
            },
        )


# ===========================================================================
# Strategy 7: MEV Bundle Composer
# ===========================================================================

class MEVBundleComposer(Strategy):
    """
    Combine multiple smaller opportunities into a single atomic
    transaction bundle.

    The RL agent learns:
    - Which opportunities can be combined (same block, same tokens)
    - Optimal ordering to maximize combined PnL
    - When bundling is worth the extra gas vs executing separately
    """

    def scan(self, market: Market) -> List[Opportunity]:
        # First, run all individual strategies
        individual_opps = []

        scanners = [
            CrossDexArbitrage(gas_price_gwei=self.gas_price_gwei, eth_price_usd=self.eth_price_usd),
            TriangularArbitrage(gas_price_gwei=self.gas_price_gwei, eth_price_usd=self.eth_price_usd),
        ]

        for scanner in scanners:
            individual_opps.extend(scanner.scan(market))

        # Try to combine compatible opportunities
        bundles = self._find_bundles(individual_opps)

        # Only return bundles that are more profitable than individual execution
        return bundles

    def _find_bundles(
        self, opportunities: List[Opportunity]
    ) -> List[Opportunity]:
        """Find opportunity pairs that can be profitably combined."""

        bundles = []
        profitable = [o for o in opportunities if o.is_profitable]

        for i in range(len(profitable)):
            for j in range(i + 1, len(profitable)):
                opp_a = profitable[i]
                opp_b = profitable[j]

                # Check compatibility (same block, overlapping tokens)
                if not self._are_compatible(opp_a, opp_b):
                    continue

                combined = self._combine_opportunities(opp_a, opp_b)
                if combined and combined.is_profitable:
                    bundles.append(combined)

        return bundles

    def _are_compatible(self, a: Opportunity, b: Opportunity) -> bool:
        """Check if two opportunities can be atomically combined."""
        # Must share at least one token for gas savings
        tokens_a = {step.token_in.symbol for step in a.path} | {step.token_out.symbol for step in a.path}
        tokens_b = {step.token_in.symbol for step in b.path} | {step.token_out.symbol for step in b.path}
        return len(tokens_a & tokens_b) > 0

    def _combine_opportunities(
        self, a: Opportunity, b: Opportunity
    ) -> Optional[Opportunity]:
        """Combine two opportunities into a single bundle."""

        combined_gross = a.gross_profit + b.gross_profit
        combined_fees = a.total_fees + b.total_fees

        # Gas savings from shared setup (approx 30% less than separate)
        individual_gas = a.gas_estimate + b.gas_estimate
        bundle_gas = int(individual_gas * 0.7)
        combined_gas_cost = self._estimate_gas_cost(
            bundle_gas, a.profit_token
        )

        combined_flash_fee = a.flash_loan_fee + b.flash_loan_fee
        combined_capital = max(a.capital_required, b.capital_required)

        return Opportunity(
            strategy_name="mev_bundle",
            path=a.path + b.path,
            profit_token=a.profit_token,
            gross_profit=combined_gross,
            total_fees=combined_fees,
            gas_cost=combined_gas_cost,
            flash_loan_fee=combined_flash_fee,
            net_profit=combined_gross - combined_fees - combined_gas_cost - combined_flash_fee,
            capital_required=combined_capital,
            uses_flash_loan=a.uses_flash_loan or b.uses_flash_loan,
            gas_estimate=bundle_gas,
            confidence=min(a.confidence, b.confidence) * 0.9,  # slightly lower
            risk_score=max(a.risk_score, b.risk_score),
            metadata={
                "sub_strategies": [a.strategy_name, b.strategy_name],
                "gas_savings_pct": 30,
            },
        )


# ===========================================================================
# Strategy Registry
# ===========================================================================

class StrategyRegistry:
    """
    Central registry for all strategies. The RL agent's observation
    space includes a summary of what the registry found each step.
    """

    def __init__(
        self,
        gas_price_gwei: float = 30.0,
        eth_price_usd: float = 2000.0,
    ):
        self.strategies: Dict[str, Strategy] = {}
        self.gas_price_gwei = gas_price_gwei
        self.eth_price_usd = eth_price_usd

        # Register all default strategies
        self._register_defaults()

    def _register_defaults(self):
        self.strategies = {
            "cross_dex": CrossDexArbitrage(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "triangular": TriangularArbitrage(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "flash_loan": FlashLoanArbitrage(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "liquidation": LiquidationHunter(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "sandwich": SandwichAttack(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "funding_rate": FundingRateArbitrage(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
            "mev_bundle": MEVBundleComposer(
                gas_price_gwei=self.gas_price_gwei,
                eth_price_usd=self.eth_price_usd,
            ),
        }

    def scan_all(self, market: Market) -> Dict[str, List[Opportunity]]:
        """Run all strategies and return results keyed by strategy name."""
        results = {}
        for name, strategy in self.strategies.items():
            try:
                results[name] = strategy.scan(market)
            except Exception as e:
                results[name] = []
        return results

    def get_all_opportunities(
        self, results: Optional[Dict[str, List[Opportunity]]] = None,
        market: Optional[Market] = None,
    ) -> List[Opportunity]:
        """Get a flat list of all opportunities, sorted by net profit."""
        if results is None and market is not None:
            results = self.scan_all(market)
        if results is None:
            return []

        all_opps = []
        for opps in results.values():
            all_opps.extend(opps)

        # Sort by net profit descending
        all_opps.sort(key=lambda o: o.net_profit, reverse=True)
        return all_opps

    def summary_vector(self, results: Dict[str, List[Opportunity]]) -> List[float]:
        """
        Produce a summary observation vector for the RL agent.

        One value per strategy:
            - number of opportunities found
            - best net profit
            - best ROI
        = 3 values * 7 strategies = 21 features
        """
        vec = []
        for name in ["cross_dex", "triangular", "flash_loan", "liquidation",
                      "sandwich", "funding_rate", "mev_bundle"]:
            opps = results.get(name, [])
            count = len(opps)
            best_pnl = max((o.net_profit for o in opps), default=0.0)
            best_roi = max((o.roi for o in opps), default=0.0)
            vec.extend([count, best_pnl, best_roi])
        return vec
