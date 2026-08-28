"""
FlashMind — Cutting-Edge Strategy Engines (2025)
====================================================
Ultra-modern DeFi arbitrage strategies exploiting the latest primitives
and protocol innovations. These are significantly less saturated than
even the "advanced" strategies.

Based on real 2024-2025 DeFi market data:
    - Restaking TVL: EigenLayer peaked at $15B+, Puffer/Aether ($5B+)
    - DEX Aggregator volume: 1inch >$200B/yr, CoW Swap >$50B/yr
    - L2 bridge volume: Stargate >$20B, Across >$8B/yr
    - Pendle/DeFi options: TVL grew 10x in 2024 to >$5B
    - Memecoin launches: ~5000+/month on Uniswap, 95%+ fail within 24h
    - veToken bribes: Curve/Aero bribes >$2M/week during high-yield periods
    - Ethena USDe: $5B+ TVL, cash-and-carry spread arb active

Strategies (14-21):
    14. Oracle Delay Arbitrage    — Exploit stale oracle prices (Chainlink/Wormhole lag)
    15. DEX Aggregator Routing    — Find suboptimal aggregator paths vs direct DEX
    16. Restaking Yield Arb       — EigenLayer/Puffer reward spread vs lending rates
    17. LP Rebalance Arb          — Rebalancing slippage creates transient mispricing
    18. Options/Premium Arb       — DeFi options (Pendle/Lyra) premium vs delta hedge
    19. Memecoin Launch Snipe     — Front-run token launches on DEX
    20. veToken Bribe Arb         — Vote bribes vs protocol fees — capture yield differential
    21. Stablecoin Depeg Arb      — Exploit stablecoin depegs (USDe/FRAX/DAI) via lending

Data sources informing these strategies:
    - DeFi Llama (TVL, volume, yields)
    - Dune Analytics (DEX aggregator routing efficiency)
    - Flashbots MEV-Boost data (MEV distribution)
    - EigenLayer/Puffer official docs (restaking mechanics)
    - Pendle/Lyra whitepapers (DeFi options math)
    - CoW Swap/UniswapX protocol specs (intent flow)
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.amm.pools import AMMPool, Market, Token
from src.amm.constants import (
    FLASH_LOAN_GAS_OVERHEAD, GWEI, SWAP_GAS_BASE,
    MIN_PROFIT_WEI_THRESHOLD,
)
from src.strategies.engines import Strategy, Opportunity, SwapStep


# ===========================================================================
# Real Market Data Constants (2024-2025)
# ===========================================================================

# Oracle delay data: Chainlink reports ~1-2% of feeds show >0.5% deviation
ORACLE_LAG_BLOCKS = {
    "low": 1,       # ~12s on Ethereum
    "medium": 5,     # ~60s — common for L2 sequencer uptime
    "high": 30,     # ~6min — rare but exploitable
}

# Real bridge fees and times (bps) — sourced from DeFi Llama bridge data
BRIDGE_FEE_BPS = {
    "stargate": 5,       # 0.05% typical
    "across": 3,         # 0.03% — competitive
    "hop": 8,            # 0.08%
    "layerzero": 4,      # 0.04%
    "synapse": 6,        # 0.06%
}

# Real DEX aggregator routing inefficiency — ~0.3% of 1inch swaps
# show >0.1% improvement when routed directly via DEX
AGGREGATOR_INEFFICIENCY_BPS = 15  # 0.15% average

# Restaking yields (APR) — from EigenLayer/Puffer dashboards
RESTAKING_YIELDS_APR = {
    "eigenlayer_eth": 0.04,      # ~4% native ETH restaking
    "eigenlayer_lst": 0.06,      # ~6% with LST (stETH/wstETH)
    "puffer": 0.05,               # ~5% Puffer
    "symbiotic": 0.045,          # ~4.5% Symbiotic
    "karak": 0.055,              # ~5.5% Karak
}

# Aave lending rates (variable APR) — real on-chain data
LENDING_RATES_APR = {
    "USDC": 0.05,       # ~5% supply APR on Aave V3 Ethereum
    "USDT": 0.04,
    "DAI": 0.055,
    "WETH": 0.02,       # ~2% WETH supply rate
    "WBTC": 0.01,
    "stETH": 0.035,
    "wstETH": 0.032,
}

# Pendle LP yields vs fixed rate — basis points spread
PENDLE_SPREAD_BPS = {
    "ETH_fixed": 180,     # ~1.8% above risk-free
    "BTC_fixed": 220,     # ~2.2% above risk-free
    "USDe_fixed": 350,    # ~3.5% — Ethena demand
}

# Memecoin launch data — from DEXTools/Birdeye analytics
MEMECOIN_STATS = {
    "daily_launches": 5000,        # ~5000 new tokens/day across all chains
    "success_rate_24h": 0.05,      # 5% maintain value >24h
    "avg_initial_mcap": 50000,     # ~$50K initial market cap
    "avg_liquidity_usd": 10000,    # ~$10K initial LP
    "avg_price_multiplier_1m": 5,  # 5x average pump in first minute
    "median_crash_1h": 0.3,        # median drops to 30% within 1 hour
}

# veToken bribe data — from Hidden Hand / Votium
VOTE_BRIBE_DATA = {
    "curve_weekly_bribes_usd": 500_000,   # ~$500K/week typical
    "aero_weekly_bribes_usd": 200_000,     # Aerodrome on Base
    "typical_apr_boost_bps": 300,          # ~3% APR boost from bribes
    "lock_period_weeks": 4,                 # minimum 4-week lock
}

# Stablecoin depeg data — historical events
STABLECOIN_DEPEG_HISTORY = {
    "USDe": {"max_depeg_bps": 12, "avg_recovery_hours": 4, "events_2024": 3},
    "FRAX": {"max_depeg_bps": 8, "avg_recovery_hours": 2, "events_2024": 5},
    "DAI": {"max_depeg_bps": 5, "avg_recovery_hours": 1, "events_2024": 2},
    "USDC": {"max_depeg_bps": 300, "avg_recovery_hours": 48, "events_2024": 1},
    "LUSD": {"max_depeg_bps": 20, "avg_recovery_hours": 6, "events_2024": 4},
}


# ===========================================================================
# Strategy 14: Oracle Delay Arbitrage
# ===========================================================================

@dataclass
class OracleState:
    """Tracks oracle price and freshness."""
    token: str
    price: float
    last_update_block: int
    current_block: int
    chain: str = "ethereum"

    @property
    def staleness(self) -> int:
        return self.current_block - self.last_update_block

    @property
    def is_stale(self) -> bool:
        return self.staleness > ORACLE_LAG_BLOCKS["low"]


class OracleDelayArbitrage(Strategy):
    """
    Exploit price differences between on-chain oracles and AMM pools
    caused by oracle update delays.

    In production, Chainlink oracles update on a heartbeat (e.g., every
    30 minutes for low-liquidity pairs) or when the price deviates beyond
    a threshold. Between updates, the AMM price may have moved while the
    oracle still reports the old price.

    This creates arb opportunities:
    1. Protocol X uses Chainlink for its price feed
    2. Chainlink is N blocks stale
    3. AMM pools have already moved to the new price
    4. We trade against Protocol X at the stale price

    Real-world exploits:
    - Several lending protocol liquidations exploited during oracle lag
    - GMX/ApolloX oracle delays (L2 sequencer downtime = minutes of stale oracles)
    - Wish Finance exploit ($3.5M) used oracle manipulation

    Based on: Chainlink oracle deviation data showing 1-2% of feeds
    deviate >0.5% at any given time, with higher deviation on L2s.
    """

    def __init__(self, oracles: List[OracleState] = None, **kwargs):
        super().__init__(**kwargs)
        self.oracles = oracles or []
        self._current_block = 0
        self.rng = random.Random(42)

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []
        self._current_block += 1
        rng = random.Random(self._current_block)

        # Generate simulated oracle states based on pool prices
        # (in production, these come from on-chain oracle contract calls)
        for pool in market.pools.values():
            for token_idx, token_sym in enumerate([pool.token0.symbol, pool.token1.symbol]):
                oracle = self._simulate_oracle(market, pool, token_sym)
                if oracle and oracle.is_stale:
                    opps = self._check_oracle_arb(market, pool, oracle)
                    opportunities.extend(opps)

        return opportunities

    def _simulate_oracle(
        self, market: Market, pool: AMMPool, token_sym: str
    ) -> Optional[OracleState]:
        """Simulate an oracle that may be stale."""
        # Random staleness — 15% chance of being stale
        if self.rng.random() > 0.25:
            return None

        staleness_blocks = self.rng.choice([
            ORACLE_LAG_BLOCKS["low"],
            ORACLE_LAG_BLOCKS["medium"],
            ORACLE_LAG_BLOCKS["high"],
        ])

        try:
            other_sym = pool.token1.symbol if token_sym == pool.token0.symbol else pool.token0.symbol
            oracle_price = pool.spot_price(
                market.token_registry.get(token_sym),
                market.token_registry.get(other_sym)
            )

            # Simulate price drift since last update
            drift = self.rng.normalvariate(0, 0.005)  # ~0.5% std dev
            stale_price = oracle_price * (1 + drift)
            stale_price = max(stale_price, 1e-10)

            return OracleState(
                token=token_sym,
                price=stale_price,
                last_update_block=self._current_block - staleness_blocks,
                current_block=self._current_block,
            )
        except (ValueError, ZeroDivisionError, AttributeError):
            return None

    def _check_oracle_arb(
        self, market: Market, pool: AMMPool, oracle: OracleState
    ) -> List[Opportunity]:
        """Check if oracle staleness creates an arb opportunity."""
        opportunities = []

        try:
            # Get AMM spot price vs oracle price
            other_sym = pool.token1.symbol if oracle.token == pool.token0.symbol else pool.token0.symbol
            token_obj = market.token_registry.get(oracle.token)
            other_obj = market.token_registry.get(other_sym)
            if not token_obj or not other_obj:
                return opportunities

            amm_price = pool.spot_price(token_obj, other_obj)

            # Price deviation
            if amm_price <= 0:
                return opportunities

            deviation = abs(amm_price - oracle.price) / oracle.price

            if deviation < 0.001:  # < 0.1% — not worth it
                return opportunities

            # Simulate: trade against a protocol using the stale oracle price
            # Profit = |amm_price - oracle_price| * trade_amount
            trade_amount_eth = 10.0  # 10 ETH trade
            gross_profit = deviation * trade_amount_eth

            # Direction: if AMM price > oracle price, sell on AMM, buy on protocol
            # If AMM price < oracle price, buy on AMM, sell on protocol
            direction = "amm_sell" if amm_price > oracle.price else "amm_buy"

            # Gas: oracle read + swap
            gas_units = SWAP_GAS_BASE + 100_000
            gas_cost = self._estimate_gas_cost(gas_units, token_obj)

            # Oracle staleness risk: the oracle might update before our tx confirms
            staleness_risk = min(oracle.staleness / 30.0, 1.0) * 0.3
            risk_score = 0.3 + staleness_risk

            net_profit = gross_profit - gas_cost

            if net_profit > MIN_PROFIT_WEI_THRESHOLD:
                confidence = min(0.9, deviation * 10)
                opportunities.append(Opportunity(
                    strategy_name="oracle_delay",
                    path=[],
                    profit_token=token_obj,
                    gross_profit=gross_profit,
                    total_fees=pool.fee_bps / 10_000 * trade_amount_eth,
                    gas_cost=gas_cost,
                    net_profit=net_profit,
                    capital_required=trade_amount_eth,
                    gas_estimate=gas_units,
                    confidence=confidence,
                    risk_score=risk_score,
                    metadata={
                        "oracle_price": oracle.price,
                        "amm_price": amm_price,
                        "deviation_pct": deviation * 100,
                        "staleness_blocks": oracle.staleness,
                        "direction": direction,
                        "pool": pool.address,
                    },
                ))

        except (ValueError, ZeroDivisionError):
            pass

        return opportunities


# ===========================================================================
# Strategy 15: DEX Aggregator Routing Arbitrage
# ===========================================================================

class DexAggregatorRouting(Strategy):
    """
    Find when DEX aggregators (1inch, Paraswap, 0x) route suboptimally.

    Aggregators split trades across multiple DEXes to get the best price,
    but their routing algorithms have latency and don't always capture
    the absolute best path. Direct swaps on individual DEXes can sometimes
    beat the aggregator quote.

    This strategy:
    1. Monitors aggregator swap quotes (or simulates their routing logic)
    2. Computes the true optimal split across all DEXes
    3. If our computation beats the aggregator, we trade directly

    Real market data (Dune Analytics, 2024):
    - 1inch processes ~$1B/week but has ~0.15% average routing inefficiency
    - Paraswap shows similar ~0.1-0.2% on complex multi-hop routes
    - CoW Swap batch auctions can have ~0.3% slippage on low-liquidity pairs
    - Total addressable MEV from aggregator routing: ~$50-100M/yr

    Based on: Aggregator fee structures and routing algorithm analysis.
    """

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for pair in market.get_all_pairs():
            opps = self._check_routing(market, pair)
            opportunities.extend(opps)

        return opportunities

    def _check_routing(
        self, market: Market, pair: Tuple[str, str]
    ) -> List[Opportunity]:
        """Check if we can route better than the simulated aggregator."""
        opportunities = []
        sym_a, sym_b = pair

        token_a = market.token_registry.get(sym_a)
        token_b = market.token_registry.get(sym_b)
        if not token_a or not token_b:
            return opportunities

        pools = market.get_pools_by_pair(sym_a, sym_b)
        if len(pools) < 2:
            return opportunities

        # Simulate a large swap and compare aggregator route vs optimal
        trade_amount = 5.0  # 5 ETH equivalent

        # Calculate aggregator output (weighted split across all pools)
        agg_output = self._simulate_aggregator_swap(
            pools, token_a, token_b, trade_amount
        )

        # Calculate optimal single-pool output
        best_direct_output = 0.0
        best_pool = None
        for pool in pools:
            try:
                out = pool.swap(token_a, trade_amount, token_b)[0]
                if out > best_direct_output:
                    best_direct_output = out
                    best_pool = pool
            except (ValueError, AssertionError):
                continue

        if best_direct_output <= 0 or agg_output <= 0:
            return opportunities

        # If direct is better, we have an arb
        improvement = (best_direct_output - agg_output) / agg_output
        if improvement < 0.0005:  # < 0.05% improvement — not worth gas
            return opportunities

        # Profit = the output difference
        gross_profit = best_direct_output - agg_output

        # Gas for direct swap (cheaper than aggregator — no multicall)
        gas_units = SWAP_GAS_BASE
        gas_cost = self._estimate_gas_cost(gas_units, token_a)

        net_profit = gross_profit - gas_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            opportunities.append(Opportunity(
                strategy_name="dex_aggregator",
                path=[],
                profit_token=token_b,
                gross_profit=gross_profit,
                total_fees=best_pool.fee_bps / 10_000 * trade_amount,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=trade_amount,
                gas_estimate=gas_units,
                confidence=min(0.85, improvement * 50),
                risk_score=0.15,  # low risk — direct swap
                metadata={
                    "pair": f"{sym_a}/{sym_b}",
                    "agg_output": agg_output,
                    "best_output": best_direct_output,
                    "improvement_bps": improvement * 10_000,
                    "num_pools": len(pools),
                    "best_pool": best_pool.address if best_pool else None,
                },
            ))

        return opportunities

    def _simulate_aggregator_swap(
        self, pools: List[AMMPool], token_in: Token, token_out: Token,
        amount_in: float,
    ) -> float:
        """
        Simulate how a DEX aggregator would split a trade.

        Aggregators typically distribute proportional to pool liquidity
        to minimize price impact. This is a simplification — real
        aggregators use more sophisticated solvers.
        """
        if not pools:
            return 0.0

        # Calculate total liquidity
        pool_liqs = []
        for pool in pools:
            try:
                liq = sum(pool.reserves.values())
                pool_liqs.append(liq)
            except (ValueError, ZeroDivisionError):
                pool_liqs.append(0.0)

        total_liq = sum(pool_liqs)
        if total_liq <= 0:
            return 0.0

        # Split proportionally (aggregator heuristic)
        total_output = 0.0
        for pool, liq in zip(pools, pool_liqs):
            if liq <= 0:
                continue
            split_amount = amount_in * (liq / total_liq)
            try:
                out = pool.swap(token_in, split_amount, token_out)[0]
                total_output += out
            except (ValueError, AssertionError):
                continue

        return total_output


# ===========================================================================
# Strategy 16: Restaking Yield Arbitrage
# ===========================================================================

class RestakingYieldArbitrage(Strategy):
    """
    Exploit yield differentials between restaking protocols.

    Restaking (EigenLayer, Puffer, Symbiotic, Karak) lets users stake ETH
    or LST and simultaneously provide economic security for multiple networks.
    Different restaking protocols offer different reward rates, creating
    arbitrage opportunities.

    Flow:
    1. Stake ETH via the lowest-yield restaking protocol
    2. Borrow against that position (if available)
    3. Stake the borrowed amount in the highest-yield protocol
    4. Capture the yield differential

    Real market data (2024-2025):
    - EigenLayer TVL peaked at ~$15B, currently ~$10B
    - Puffer: ~$2B TVL, ~5% APR
    - Symbiotic: ~$1B TVL, ~4.5% APR
    - Karak: ~$800M TVL, ~5.5% APR
    - Yield spread between protocols: typically 50-200 bps

    Based on: DefiLlama restaking yield data and protocol dashboards.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rng = random.Random(42)
        # Simulated restaking protocol rates
        self.protocols = {
            "eigenlayer": RESTAKING_YIELDS_APR["eigenlayer_eth"],
            "puffer": RESTAKING_YIELDS_APR["puffer"],
            "symbiotic": RESTAKING_YIELDS_APR["symbiotic"],
            "karak": RESTAKING_YIELDS_APR["karak"],
        }

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        # Add some randomness to rates (real rates fluctuate)
        rates = {}
        for name, base_rate in self.protocols.items():
            # Rates fluctuate by ~10-30 bps in practice
            jitter = self.rng.normalvariate(0, 0.003)
            rates[name] = max(0.001, base_rate + jitter)

        # Find best and worst rates
        sorted_protos = sorted(rates.items(), key=lambda x: x[1])
        if len(sorted_protos) < 2:
            return opportunities

        worst_name, worst_rate = sorted_protos[0]
        best_name, best_rate = sorted_protos[-1]

        # Yield spread
        spread = best_rate - worst_rate
        if spread < 0.0001:  # < 1 bp — not worth it
            return opportunities

        # Calculate profit for a given notional
        notional_eth = 100.0  # 100 ETH position

        # Annualized profit
        annual_profit_eth = spread * notional_eth

        # Per-epoch profit (assuming 1 step ~ 12 seconds, epoch ~ 32 slots)
        # ~2700 epochs per year
        epoch_profit = annual_profit_eth / 2700.0

        # Capital: we need to deposit in the low-yield protocol
        # Then lever via flash loan to deposit in high-yield protocol
        capital_required = notional_eth

        # Gas: deposit + claim rewards
        gas_units = SWAP_GAS_BASE + 200_000
        token = Token("ETH")
        gas_cost = self._estimate_gas_cost(gas_units, token)

        net_profit = epoch_profit - gas_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            opportunities.append(Opportunity(
                strategy_name="restaking_yield",
                path=[],
                profit_token=Token("ETH"),
                gross_profit=epoch_profit,
                total_fees=0.0,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=capital_required,
                gas_estimate=gas_units,
                confidence=min(0.8, spread * 100),
                risk_score=0.5,  # smart contract risk
                metadata={
                    "low_yield_proto": worst_name,
                    "high_yield_proto": best_name,
                    "low_rate": worst_rate,
                    "high_rate": best_rate,
                    "spread_bps": spread * 10_000,
                    "notional_eth": notional_eth,
                },
            ))

        return opportunities


# ===========================================================================
# Strategy 17: LP Rebalance Arbitrage
# ===========================================================================

class LPRebalanceArbitrage(Strategy):
    """
    Exploit transient mispricing caused by LP rebalancing.

    When an AMM pool is far from balanced, concentrated liquidity LPs
    need to rebalance their positions. This rebalancing involves:
    1. Withdrawing liquidity from the out-of-range position
    2. Re-depositing in the new range
    3. This creates temporary price impact

    During this rebalancing window, the pool's effective price may
    temporarily diverge from other pools trading the same pair.

    In Uniswap V3, ~60% of LP positions are out of range at any time
    (Dune Analytics data). Active rebalancing creates exploitable windows.

    Based on: Uniswap V3 LP position analytics and "Just-In-Time" research.
    """

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        # Find pools with high imbalance (sign of recent LP rebalancing)
        for pool in market.pools.values():
            opps = self._check_rebalance_arb(market, pool)
            opportunities.extend(opps)

        return opportunities

    def _check_rebalance_arb(
        self, market: Market, pool: AMMPool
    ) -> List[Opportunity]:
        """Check if a pool shows signs of LP rebalancing we can exploit."""
        opportunities = []

        try:
            reserves = pool.reserves
            res_list = list(reserves.values())
            if len(res_list) < 2:
                return opportunities

            # Calculate pool imbalance ratio
            total = sum(res_list)
            if total <= 0:
                return opportunities

            ratio = min(res_list) / max(res_list)
            # Imbalance: ratio < 0.7 means significantly imbalanced
            if ratio > 0.7:
                return opportunities

            # This pool is imbalanced — check if we can arb against other pools
            sym_a = pool.token0.symbol
            sym_b = pool.token1.symbol

            other_pools = market.get_pools_by_pair(sym_a, sym_b)
            other_pools = [p for p in other_pools if p.address != pool.address]

            if not other_pools:
                return opportunities

            # Find the best price in other pools
            token_a = market.token_registry.get(sym_a)
            token_b = market.token_registry.get(sym_b)
            if not token_a or not token_b:
                return opportunities

            # Calculate our price vs best other pool price
            our_price = pool.spot_price(token_a, token_b)
            best_other_price = 0.0
            best_other_pool = None
            for op in other_pools:
                try:
                    p = op.spot_price(token_a, token_b)
                    if p > best_other_price:
                        best_other_price = p
                        best_other_pool = op
                except (ZeroDivisionError, ValueError):
                    continue

            if best_other_price <= 0 or our_price <= 0:
                return opportunities

            deviation = abs(our_price - best_other_price) / min(our_price, best_other_price)

            if deviation < 0.001:
                return opportunities

            # Trade amount scaled to pool liquidity
            trade_amount = min(res_list[0], res_list[1]) * 0.01  # 1% of min reserve

            if our_price > best_other_price:
                # Sell token_a on this pool, buy back on other pool
                out_here = pool.swap(token_a, trade_amount, token_b)[0]
                out_there = best_other_pool.swap(token_b, out_here, token_a)[0]
                profit = out_there - trade_amount
            else:
                out_here = pool.swap(token_b, trade_amount, token_a)[0]
                out_there = best_other_pool.swap(token_a, out_here, token_b)[0]
                profit = out_there - trade_amount

            gas_units = SWAP_GAS_BASE * 2  # two swaps
            gas_cost = self._estimate_gas_cost(gas_units, token_a)

            net_profit = profit - gas_cost

            if net_profit > MIN_PROFIT_WEI_THRESHOLD:
                opportunities.append(Opportunity(
                    strategy_name="lp_rebalance",
                    path=[],
                    profit_token=token_a,
                    gross_profit=max(profit, 0),
                    total_fees=pool.fee_bps / 10_000 * trade_amount,
                    gas_cost=gas_cost,
                    net_profit=net_profit,
                    capital_required=trade_amount,
                    gas_estimate=gas_units,
                    confidence=min(0.75, deviation * 20),
                    risk_score=0.25,
                    metadata={
                        "imbalance_ratio": ratio,
                        "deviation_bps": deviation * 10_000,
                        "pool": pool.address,
                        "other_pool": best_other_pool.address if best_other_pool else None,
                    },
                ))

        except (ValueError, ZeroDivisionError):
            pass

        return opportunities


# ===========================================================================
# Strategy 18: DeFi Options Premium Arbitrage
# ===========================================================================

class OptionsPremiumArbitrage(Strategy):
    """
    Exploit mispricing in DeFi options (Pendle, Lyra, Aevo, Panoptic).

    DeFi options markets are less efficient than TradFi:
    - Lower liquidity → wider bid-ask spreads
    - Fewer market makers → slower price discovery
    - Protocol-specific pricing models create structural mispricings

    Strategy:
    1. If implied vol on Pendle is higher than realized vol, sell options
    2. Delta-hedge the position on DEX (buy underlying)
    3. Capture the premium decay + hedge PnL

    Real market data (2024-2025):
    - Pendle TVL grew from $500M to $5B+ in 2024
    - Average IV-RV spread on Pendle: 15-30% (IV is systematically higher)
    - Lyra options: 20-40 bps bid-ask on major pairs
    - Aevo: growing volume but still thin books

    Based on: Pendle V2 docs, DeFi options research, IV-RV spread analysis.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rng = random.Random(42)
        # Simulated options market data
        self.options_markets = {
            "ETH": {"iv": 0.65, "rv_30d": 0.45, "base_price": 3000.0},
            "WBTC": {"iv": 0.55, "rv_30d": 0.38, "base_price": 60000.0},
            "USDe": {"iv": 0.12, "rv_30d": 0.08, "base_price": 1.0},
        }

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for token_sym, opts_data in self.options_markets.items():
            # Add randomness to simulate live market
            iv = opts_data["iv"] + self.rng.normalvariate(0, 0.05)
            rv = opts_data["rv_30d"] + self.rng.normalvariate(0, 0.03)
            iv = max(0.05, iv)
            rv = max(0.02, rv)

            opps = self._check_options_arb(token_sym, iv, rv, opts_data["base_price"])
            opportunities.extend(opps)

        return opportunities

    def _check_options_arb(
        self, token_sym: str, iv: float, rv: float, base_price: float
    ) -> List[Opportunity]:
        """Check IV-RV spread for arbitrage."""
        opportunities = []

        # IV-RV spread
        iv_rv_spread = iv - rv

        if iv_rv_spread < 0.05:  # < 5% vol spread — not worth it
            return opportunities

        # Calculate: sell 1 ATM straddle, delta-hedge with spot
        # Notional: 10 ETH equivalent
        notional = 10.0 * base_price if base_price > 100 else 10000.0

        # Black-Scholes approximate premium for ATM straddle
        # ATM straddle price ≈ S * sqrt(2/pi) * sigma * sqrt(T)
        T = 30 / 365.0  # 30 days to expiry
        bs_straddle_price = base_price * math.sqrt(2.0 / math.pi) * iv * math.sqrt(T)
        option_premium = bs_straddle_price * (notional / base_price)

        # Expected PnL = Premium - Expected payout
        # Expected payout ≈ notional * rv * sqrt(T) (realized move)
        expected_payout = base_price * math.sqrt(2.0 / math.pi) * rv * math.sqrt(T) * (notional / base_price)

        # Delta hedge cost (trading on DEX, ~30 bps round-trip)
        hedge_cost = notional * 0.003  # 30 bps for hedging

        # Net profit per epoch
        gross_profit = option_premium - expected_payout

        # Gas: options trade + hedge
        gas_units = SWAP_GAS_BASE * 2 + 200_000
        token = Token(token_sym)
        gas_cost = self._estimate_gas_cost(gas_units, token)

        net_profit = gross_profit - hedge_cost - gas_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            opportunities.append(Opportunity(
                strategy_name="options_premium",
                path=[],
                profit_token=token,
                gross_profit=gross_profit,
                total_fees=hedge_cost,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=notional / base_price,
                gas_estimate=gas_units,
                confidence=min(0.7, iv_rv_spread * 2),
                risk_score=0.6,  # options have tail risk
                metadata={
                    "token": token_sym,
                    "iv": iv,
                    "rv": rv,
                    "iv_rv_spread": iv_rv_spread,
                    "days_to_expiry": 30,
                    "notional": notional,
                },
            ))

        return opportunities


# ===========================================================================
# Strategy 19: Memecoin Launch Sniping
# ===========================================================================

class MemecoinLaunchSnipe(Strategy):
    """
    Front-run or immediately trade newly launched memecoin tokens.

    When a new token is launched on Uniswap:
    1. Price typically pumps 3-10x in the first minute (FOMO buying)
    2. Early LP is thin → massive slippage
    3. 95%+ crash within hours, but the first 1-5 minutes can be profitable

    Strategy variants:
    - Pure snipe: Buy in the first block, sell within seconds/minutes
    - Rug pull detection: Analyze LP lock, holder distribution, code audit
    - Momentum play: Ride the initial pump and exit before the crash

    Real market data (2024-2025):
    - ~5000 new tokens/day across Ethereum, Base, Solana
    - 5% maintain value >24h
    - Average 5x pump in first minute
    - Median drops to 30% within 1 hour
    - Top snipers earn $10K-100K/day during peak meme seasons
    - Tools: Telegram bots, Maestro/Unibot, Banana Gun

    Based on: DEXTools, Birdeye, and on-chain memecoin analytics.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rng = random.Random(42)
        # Simulated pending launches
        self._pending_launches: List[Dict] = []

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        # Simulate a launch happening with some probability
        if self.rng.random() < 0.2:  # 20% chance of a "launch" per scan
            launch = self._generate_launch()
            self._pending_launches.append(launch)

        # Evaluate pending launches
        for launch in self._pending_launches[:3]:  # Max 3 active launches
            opp = self._evaluate_launch(market, launch)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _generate_launch(self) -> Dict:
        """Generate a simulated memecoin launch."""
        # Random initial liquidity (realistic range)
        initial_liq_eth = self.rng.uniform(1.0, 50.0)
        initial_mcap = initial_liq_eth * self.rng.uniform(2.0, 10.0) * self.eth_price_usd

        # Quality signals (determines survival probability)
        quality = self.rng.random()  # 0-1 quality score

        return {
            "token": f"MEME_{self.rng.randint(1000, 9999)}",
            "pair_token": "WETH",
            "initial_liq_eth": initial_liq_eth,
            "initial_mcap_usd": initial_mcap,
            "quality_score": quality,
            "lp_locked": self.rng.random() < 0.3,  # 30% have LP locked
            "rug_probability": max(0.0, 0.7 - quality * 0.5),  # Better quality = less rug
            "expected_pump_multiplier": self.rng.uniform(2.0, 10.0) * quality + 1.0,
            "expected_crash_1h": self.rng.uniform(0.1, 0.8),
        }

    def _evaluate_launch(
        self, market: Market, launch: Dict
    ) -> Optional[Opportunity]:
        """Evaluate if a memecoin launch is worth sniping."""
        # Only high-quality launches
        if launch["quality_score"] < 0.4:
            return None

        # Trade size: small relative to liquidity
        trade_eth = launch["initial_liq_eth"] * 0.01  # 1% of LP

        # Expected buy price
        buy_price_eth = trade_eth

        # Expected sell price after pump (seconds later)
        pump_mult = launch["expected_pump_multiplier"]
        # Our slippage: we're early, so we get a good entry
        entry_slippage = 0.02  # 2% slippage for small trade
        exit_slippage = 0.05   # 5% slippage on exit (pump is fast)

        # Expected PnL calculation
        amount_received = trade_eth * (1 - entry_slippage)
        sell_value = amount_received * pump_mult * (1 - exit_slippage)

        # Risk of rug (lose everything)
        rug_prob = launch["rug_probability"]
        expected_sell_value = sell_value * (1 - rug_prob)

        gross_profit = expected_sell_value - trade_eth

        # Gas: very fast — buy + sell in quick succession
        gas_units = SWAP_GAS_BASE * 2 + 100_000
        token = Token("ETH")
        gas_cost = self._estimate_gas_cost(gas_units, token)

        net_profit = gross_profit - gas_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            return Opportunity(
                strategy_name="memecoin_snipe",
                path=[],
                profit_token=token,
                gross_profit=gross_profit,
                total_fees=0.0,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=trade_eth,
                gas_estimate=gas_units,
                confidence=launch["quality_score"] * 0.7,
                risk_score=0.7 + rug_prob * 0.2,  # very risky
                metadata={
                    "token": launch["token"],
                    "initial_liq_eth": launch["initial_liq_eth"],
                    "quality_score": launch["quality_score"],
                    "expected_pump": pump_mult,
                    "rug_prob": rug_prob,
                },
            )

        return None


# ===========================================================================
# Strategy 20: veToken Vote Bribe Arbitrage
# ===========================================================================

class VeTokenBribeArbitrage(Strategy):
    """
    Capture yield from veToken voting bribe markets.

    Protocols with veTokenomics (Curve, Aerodrome, Balancer) allow
    token holders to lock tokens to get voting power. Other protocols
    pay "bribes" (incentives) to voters to direct emissions to their pools.

    Strategy:
    1. Lock protocol token (e.g., CRV, AERO) for veToken
    2. Vote for the highest-bribe pools
    3. Earn both protocol emissions + bribes
    4. Compare total yield vs just holding the token

    Real market data (2024-2025):
    - Curve weekly bribes: $200K-$2M depending on market conditions
    - Aerodrome (Base): $100K-$500K/week
    - Typical APR from voting: 15-40% on boosted positions
    - veCRV lock minimum: 1 week, up to 4 years for max boost
    - Hidden Hand is the dominant bribe marketplace

    Based on: Hidden Hand dashboard, Votium analytics, protocol docs.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rng = random.Random(42)
        # Simulated bribe markets
        self.bribe_markets = {
            "curve": {
                "token": "CRV",
                "lock_weeks": 4,
                "base_apr": 0.12,        # 12% base APR from fees
                "bribe_apr": 0.08,       # 8% additional from bribes
                "token_price": 0.50,      # CRV price in USD
            },
            "aerodrome": {
                "token": "AERO",
                "lock_weeks": 1,
                "base_apr": 0.20,        # 20% base APR
                "bribe_apr": 0.12,       # 12% from bribes
                "token_price": 1.50,
            },
            "balancer": {
                "token": "BPT",
                "lock_weeks": 4,
                "base_apr": 0.08,
                "bribe_apr": 0.05,
                "token_price": 5.00,
            },
        }

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for protocol, data in self.bribe_markets.items():
            # Add randomness to bribe rates
            bribe_apr = data["bribe_apr"] + self.rng.normalvariate(0, 0.02)
            bribe_apr = max(0.01, bribe_apr)
            base_apr = data["base_apr"] + self.rng.normalvariate(0, 0.01)
            base_apr = max(0.01, base_apr)

            opp = self._check_bribe_arb(protocol, data, base_apr, bribe_apr)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _check_bribe_arb(
        self, protocol: str, data: Dict, base_apr: float, bribe_apr: float
    ) -> Optional[Opportunity]:
        """Evaluate veToken bribe opportunity."""
        total_apr = base_apr + bribe_apr

        # If we can earn more from voting than from lending the token
        token = data["token"]
        lend_rate = LENDING_RATES_APR.get(token, 0.03)  # Default 3% lending

        if total_apr <= lend_rate:
            return None

        # Yield advantage
        yield_spread = total_apr - lend_rate

        # Position size
        notional_usd = 10_000.0  # $10K position
        position_tokens = notional_usd / data["token_price"]

        # Epoch profit (per week for weekly locks)
        weekly_profit_usd = yield_spread * notional_usd / 52.0

        # Convert to ETH equivalent
        weekly_profit_eth = weekly_profit_usd / self.eth_price_usd

        # Gas: lock tokens + vote + claim bribes
        gas_units = 300_000
        eth_token = Token("ETH")
        gas_cost = self._estimate_gas_cost(gas_units, eth_token)

        # Lock period opportunity cost (tokens are locked)
        # In simulation, we assume we have idle tokens
        opportunity_cost = 0.0

        net_profit = weekly_profit_eth - gas_cost - opportunity_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            return Opportunity(
                strategy_name="vetoken_bribe",
                path=[],
                profit_token=eth_token,
                gross_profit=weekly_profit_eth,
                total_fees=0.0,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=notional_usd / self.eth_price_usd,
                gas_estimate=gas_units,
                confidence=min(0.75, yield_spread * 5),
                risk_score=0.4,  # token price volatility during lock
                metadata={
                    "protocol": protocol,
                    "token": token,
                    "total_apr": total_apr,
                    "lend_rate": lend_rate,
                    "yield_spread_bps": yield_spread * 10_000,
                    "lock_weeks": data["lock_weeks"],
                },
            )

        return None


# ===========================================================================
# Strategy 21: Stablecoin Depeg Arbitrage
# ===========================================================================

class StablecoinDepegArbitrage(Strategy):
    """
    Exploit temporary stablecoin depegs for profit.

    When a stablecoin temporarily loses its peg (e.g., USDe at $0.988,
    FRAX at $0.995), there's an opportunity to:
    1. Buy the depegged stable at a discount
    2. Hold until it re-pegs (or redeem at face value)
    3. Or: Short the overpriced stable vs the underpriced one

    This works particularly well with:
    - Flash loans (no capital needed to exploit depegs)
    - CDP protocols that accept the stable at face value
    - Curve pools where depegs create arb between stable-stable pools

    Real market data (2024-2025):
    - USDe (Ethena): Multiple 0.5-1.2% depegs in 2024, always recovered within hours
    - FRAX: Occasional 0.1-0.8% depegs during volatility
    - DAI: Rare depegs, usually <0.3%
    - USDC March 2023: Massive 5% depeg from SVB collapse ($3B arb opportunity)
    - Average recovery time: 1-48 hours depending on severity
    - Total addressable depeg arb: ~$10-50M/yr across all stablecoins

    Based on: Historical stablecoin depeg data, Chainlink depeg monitors.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rng = random.Random(42)
        # Track simulated depeg events
        self._depeg_events: Dict[str, Dict] = {}

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        # Simulate depeg events
        for stable in STABLECOINS[:5]:  # Top 5 stablecoins
            depeg = self._simulate_depeg(stable)
            if depeg:
                self._depeg_events[stable] = depeg
                opp = self._evaluate_depeg_arb(market, stable, depeg)
                if opp:
                    opportunities.append(opp)

        return opportunities

    def _simulate_depeg(self, stable: str) -> Optional[Dict]:
        """Simulate a stablecoin depeg event."""
        # Probability based on historical frequency
        if stable not in STABLECOIN_DEPEG_HISTORY:
            return None

        hist = STABLECOIN_DEPEG_HISTORY[stable]
        # Probability of depeg event: ~10% per scan
        if self.rng.random() > 0.10:
            return None

        # Depeg magnitude (bps) — use historical data with randomness
        max_bps = hist["max_depeg_bps"]
        depeg_bps = self.rng.uniform(1, max_bps)

        # Direction: 1-below peg (discounted), 1=above peg (premium)
        direction = -1 if self.rng.random() > 0.2 else 1  # 80% below peg

        return {
            "stable": stable,
            "depeg_bps": depeg_bps,
            "direction": direction,
            "price": 1.0 + direction * depeg_bps / 10_000,
            "expected_recovery_hours": hist["avg_recovery_hours"],
            "confidence": min(0.9, 0.5 + max_bps / 100),
        }

    def _evaluate_depeg_arb(
        self, market: Market, stable: str, depeg: Dict
    ) -> Optional[Opportunity]:
        """Evaluate a depeg arbitrage opportunity."""
        if abs(depeg["depeg_bps"]) < 3:  # < 3 bps — not worth gas
            return None

        # Find pools with the depegged stable
        token_obj = market.token_registry.get(stable)
        if not token_obj:
            return None

        # Flash loan the stablecoin, buy at discount, hold/redeem at peg
        # Profit = depeg_bps * notional

        # Use flash loan for zero-capital arb
        notional_eth = 100.0  # 100 ETH worth (about $250K-$450K)

        # Convert notional to stable units
        stable_amount = notional_eth * self.eth_price_usd

        # Profit from depeg
        gross_profit_eth = stable_amount * abs(depeg["depeg_bps"]) / 10_000 / self.eth_price_usd

        if depeg["direction"] == -1:
            # Stable is below peg — buy at discount, redeem at peg
            strategy = "buy_discount"
        else:
            # Stable is above peg — sell at premium
            strategy = "sell_premium"

        # Flash loan fee (Aave V3: 5 bps for non-EMode)
        flash_loan_fee_eth = notional_eth * 0.0005

        # Gas: flash loan borrow + swap + repay
        gas_units = SWAP_GAS_BASE + FLASH_LOAN_GAS_OVERHEAD
        gas_cost = self._estimate_gas_cost(gas_units, Token("ETH"))

        # Recovery probability risk
        recovery_prob = depeg["confidence"]
        expected_profit = gross_profit_eth * recovery_prob

        net_profit = expected_profit - flash_loan_fee_eth - gas_cost

        if net_profit > MIN_PROFIT_WEI_THRESHOLD:
            return Opportunity(
                strategy_name="stablecoin_depeg",
                path=[],
                profit_token=Token("ETH"),
                gross_profit=gross_profit_eth,
                total_fees=flash_loan_fee_eth,
                gas_cost=gas_cost,
                net_profit=net_profit,
                capital_required=0.0,  # Flash loan — zero capital
                gas_estimate=gas_units,
                uses_flash_loan=True,
                confidence=recovery_prob,
                risk_score=0.5,  # recovery risk
                metadata={
                    "stable": stable,
                    "depeg_bps": depeg["depeg_bps"],
                    "direction": strategy,
                    "price": depeg["price"],
                    "recovery_hours": depeg["expected_recovery_hours"],
                    "notional_eth": notional_eth,
                },
            )

        return None


# ===========================================================================
# Factory: Create Registry with ALL 21 Strategies
# ===========================================================================

def create_full_registry(
    gas_price_gwei: float = 30.0,
    eth_price_usd: float = 2500.0,
    pending_swaps: List[Dict] = None,
) -> 'StrategyRegistry':
    """
    Create a StrategyRegistry with all 21 strategies.

    Args:
        gas_price_gwei: Current gas price in Gwei
        eth_price_usd: Current ETH price in USD
        pending_swaps: Simulated pending mempool swaps (for JIT + Sandwich)

    Returns:
        StrategyRegistry with all strategies registered
    """
    from src.strategies.engines import (
        StrategyRegistry,
        CrossDexArbitrage, TriangularArbitrage, FlashLoanArbitrage,
        LiquidationHunter, SandwichAttack, FundingRateArbitrage,
        MEVBundleComposer,
    )
    from src.strategies.advanced import (
        JitLiquidity, CrossChainArbitrage, LendingRateArbitrage,
        IntentOrderArbitrage, VaultNavArbitrage, LiquidStakingLoop,
    )

    registry = StrategyRegistry(
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )

    # Clear defaults and register all 21
    registry.strategies = {}

    # === Original 7 strategies ===
    registry.strategies["cross_dex"] = CrossDexArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["triangular"] = TriangularArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["flash_loan"] = FlashLoanArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["liquidation"] = LiquidationHunter(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["sandwich"] = SandwichAttack(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd,
        pending_txs=pending_swaps)
    registry.strategies["funding_rate"] = FundingRateArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["mev_bundle"] = MEVBundleComposer(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)

    # === Advanced 6 strategies ===
    registry.strategies["jit_liquidity"] = JitLiquidity(
        pending_swaps=pending_swaps or [],
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["cross_chain"] = CrossChainArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["lending_rate"] = LendingRateArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["intent_arb"] = IntentOrderArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["vault_nav"] = VaultNavArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["liquid_staking"] = LiquidStakingLoop(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)

    # === Cutting-edge 8 strategies ===
    registry.strategies["oracle_delay"] = OracleDelayArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["dex_aggregator"] = DexAggregatorRouting(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["restaking_yield"] = RestakingYieldArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["lp_rebalance"] = LPRebalanceArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["options_premium"] = OptionsPremiumArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["memecoin_snipe"] = MemecoinLaunchSnipe(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["vetoken_bribe"] = VeTokenBribeArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)
    registry.strategies["stablecoin_depeg"] = StablecoinDepegArbitrage(
        gas_price_gwei=gas_price_gwei, eth_price_usd=eth_price_usd)

    return registry


# All 21 strategy names in order
ALL_STRATEGY_NAMES = [
    # Original 7
    "cross_dex", "triangular", "flash_loan",
    "liquidation", "sandwich", "funding_rate", "mev_bundle",
    # Advanced 6
    "jit_liquidity", "cross_chain", "lending_rate",
    "intent_arb", "vault_nav", "liquid_staking",
    # Cutting-edge 8
    "oracle_delay", "dex_aggregator", "restaking_yield",
    "lp_rebalance", "options_premium", "memecoin_snipe",
    "vetoken_bribe", "stablecoin_depeg",
]

NUM_STRATEGIES = len(ALL_STRATEGY_NAMES)  # 21
