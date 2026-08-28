"""
FlashMind — Advanced Strategy Engines (2025)
==============================================
Cutting-edge strategies that are significantly less saturated than
traditional cross-DEX or sandwich attacks. These exploit structural
inefficiencies that fewer bots are monitoring.

Strategies:
    8.  JIT Liquidity Provision    — Provide LP right before a swap, remove after
    9.  Cross-Chain Arbitrage      — Bridge tokens across chains to exploit spread
    10. Lending Rate Arbitrage      — Borrow low-rate, lend high-rate (carry trade)
    11. Intent/CoW Order Arb       — Monitor off-chain intent flows for mispricing
    12. Vault/NAV Arbitrage         — Vault share price vs underlying asset NAV
    13. Liquid Staking Loop         — Leveraged staking yield via looping stETH

Why these are less saturated:
    - Require multi-protocol / cross-domain knowledge
    - Higher complexity → fewer competitors
    - Some are directional (not pure arb) → need risk management
    - Newer primitives (intents, restaking) → bot ecosystem still forming
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.amm.pools import AMMPool, Market, Token
from src.amm.constants import (
    FLASH_LOAN_GAS_OVERHEAD, GWEI, SWAP_GAS_BASE,
    MIN_PROFIT_WEI_THRESHOLD,
)
from src.strategies.engines import Strategy, Opportunity, SwapStep, CDPPosition


# ===========================================================================
# Strategy 8: Just-In-Time (JIT) Liquidity Provision
# ===========================================================================

class JitLiquidity(Strategy):
    """
    Monitor the mempool for incoming large swaps, then:
    1. Provide liquidity to the pool RIGHT BEFORE the swap executes
    2. Earn the swap fee (and potentially the price improvement)
    3. Remove liquidity immediately after the swap

    This is the 2024-2025 evolution of sandwich attacks. Instead of
    front-running (which competes with every MEV bot), you become a
    temporary LP. Advantages:
    - Lower gas (single mint + burn vs 2 swaps)
    - Less visible to anti-MEV detection
    - Earns fees rather than extracting from the user (socially better)
    - Still highly profitable for large swaps with concentrated liquidity

    Requires: Uniswap V3-style concentrated liquidity pools.
    """

    def __init__(self, pending_swaps: List[Dict] = None, **kwargs):
        super().__init__(**kwargs)
        self.pending_swaps = pending_swaps or []

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for tx in self.pending_swaps:
            opp = self._evaluate_jit(market, tx)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_jit(
        self, market: Market, tx: Dict
    ) -> Optional[Opportunity]:
        """
        Evaluate a JIT liquidity opportunity for a pending swap.

        tx contains: pool, token_in, token_out, amount_in
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

        best_opp = None
        best_pnl = 0.0

        # JIT works best on V3-style pools (concentrated liquidity)
        # We simulate by providing liquidity in a tight range around
        # the current price, capturing the swap fee

        for size_factor in [0.5, 1.0, 2.0, 5.0, 10.0]:
            lp_amount = victim_amount * size_factor

            try:
                # Step 1: Calculate fee earned by being LP during the swap
                # Fee = victim_amount * fee_bps / 10000 * our_share_of_liquidity
                fee_bps = pool.fee_bps
                total_liquidity = sum(pool.reserves.values())

                if total_liquidity <= 0:
                    continue

                our_share = lp_amount / (total_liquidity + lp_amount)

                # Fee earned from victim's swap
                swap_fee = victim_amount * fee_bps / 10_000
                our_fee = swap_fee * our_share

                # Price improvement: our LP position also captures the
                # price movement from the swap
                # Estimate: swap moves price by ~victim_amount / total_liquidity
                price_impact = victim_amount / (total_liquidity + victim_amount)
                price_improvement_profit = lp_amount * price_impact * 0.3  # rough

                # Capital efficiency: we only need capital for LP range
                # (concentrated = less capital than full range)
                concentrated_capital = lp_amount * 0.1  # 10x concentration factor

                gross_profit = our_fee + price_improvement_profit

                # Gas: mint position + collect fees + burn position
                gas_units = 350_000
                gas_cost = self._estimate_gas_cost(gas_units, token_in)

                # LP withdrawal slippage (minor risk)
                slippage_cost = lp_amount * 0.001 * price_impact

                net_profit = gross_profit - gas_cost - slippage_cost

                if net_profit > best_pnl:
                    best_pnl = net_profit
                    best_opp = Opportunity(
                        strategy_name="jit_liquidity",
                        path=[],
                        profit_token=token_in,
                        gross_profit=gross_profit,
                        total_fees=0.0,
                        gas_cost=gas_cost,
                        net_profit=net_profit,
                        capital_required=concentrated_capital,
                        gas_estimate=gas_units,
                        confidence=0.6,  # depends on block inclusion timing
                        risk_score=0.4,  # lower than sandwich — LP is legitimate
                        metadata={
                            "victim_amount": victim_amount,
                            "lp_amount": lp_amount,
                            "concentrated_capital": concentrated_capital,
                            "our_fee": our_fee,
                            "pool": pool.address,
                            "protocol": pool.protocol,
                        },
                    )
            except (ValueError, ZeroDivisionError):
                continue

        return best_opp


# ===========================================================================
# Strategy 9: Cross-Chain Arbitrage
# ===========================================================================

@dataclass
class BridgeQuote:
    """Quote from a cross-chain bridge."""
    bridge_name: str
    src_chain: str
    dst_chain: str
    token: str
    amount: float
    output_amount: float
    fee: float
    estimated_time_seconds: float
    reliability_score: float  # 0-1, based on historical fills

    @property
    def effective_rate(self) -> float:
        if self.amount <= 0:
            return 0.0
        return self.output_amount / self.amount


class CrossChainArbitrage(Strategy):
    """
    Exploit price differences for the same token across different chains.

    Flow:
    1. Buy token on Chain A (where it's cheaper)
    2. Bridge to Chain B via Stargate/Across/Hop/LayerZero
    3. Sell on Chain B (where it's more expensive)
    4. (Optional) Bridge profit back to original chain

    Why it's less saturated:
    - Requires running nodes/connections on multiple chains
    - Bridge execution has latency (minutes, not seconds)
    - Need to manage inventory on multiple chains
    - Execution risk: bridge could fail, price could move during transit
    - Fewer bots have multi-chain infrastructure

    We model: Ethereum ↔ Arbitrum ↔ Optimism ↔ Base ↔ Polygon
    """

    CHAIN_NAMES = ["ethereum", "arbitrum", "optimism", "base", "polygon"]
    CHAIN_ID_MAP = {
        "ethereum": 1, "arbitrum": 42161,
        "optimism": 10, "base": 8453, "polygon": 137,
    }

    def __init__(
        self,
        chain_markets: Optional[Dict[str, Market]] = None,
        bridge_quotes: Optional[List[BridgeQuote]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.chain_markets = chain_markets or {}
        self.bridge_quotes = bridge_quotes or self._default_bridges()

    def _default_bridges(self) -> List[BridgeQuote]:
        """Generate sample bridge quotes."""
        bridges = []
        for src in self.CHAIN_NAMES:
            for dst in self.CHAIN_NAMES:
                if src == dst:
                    continue
                bridges.append(BridgeQuote(
                    bridge_name="stargate",
                    src_chain=src, dst_chain=dst,
                    token="USDC",
                    amount=100_000.0,
                    output_amount=99_800.0,  # 0.2% bridge fee
                    fee=200.0,
                    estimated_time_seconds=300.0,
                    reliability_score=0.98,
                ))
                bridges.append(BridgeQuote(
                    bridge_name="across",
                    src_chain=src, dst_chain=dst,
                    token="WETH",
                    amount=10.0,
                    output_amount=9.97,  # 0.3% fee
                    fee=0.03,
                    estimated_time_seconds=600.0,
                    reliability_score=0.95,
                ))
        return bridges

    def scan(self, market: Market) -> List[Opportunity]:
        """
        Scan cross-chain opportunities.

        We use the primary market as one chain and model other chains
        with price offsets (simulating real cross-chain price divergence).
        """
        opportunities = []

        # Get all tokens with multiple chain exposure
        for token_sym in ["WETH", "USDC", "ARB", "OP"]:
            opp = self._evaluate_cross_chain(market, token_sym)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_cross_chain(
        self, primary_market: Market, token_sym: str
    ) -> Optional[Opportunity]:
        """Evaluate cross-chain arb for a specific token."""
        token = primary_market.token_registry.get(token_sym)
        if not token:
            return None

        best_opp = None
        best_pnl = 0.0

        for bridge in self.bridge_quotes:
            if bridge.token != token_sym:
                continue

            # Get price on primary chain
            try:
                primary_price = primary_market.price_between(
                    token_sym, "USDC"
                )
            except Exception:
                continue

            if primary_price <= 0:
                continue

            # Simulate price on destination chain (with random offset)
            # In production, this would be fetched from the destination chain's pools
            import random
            rng = random.Random(hash(token_sym + bridge.dst_chain))
            price_offset = rng.uniform(-0.03, 0.03)  # up to 3% divergence
            dst_price = primary_price * (1.0 + price_offset)

            # Check if arb is viable
            trade_amount = bridge.amount

            # Buy on cheaper chain, sell on expensive
            if primary_price < dst_price:
                buy_chain, sell_chain = "primary", bridge.dst_chain
                buy_price, sell_price = primary_price, dst_price
            else:
                buy_chain, sell_chain = bridge.dst_chain, "primary"
                buy_price, sell_price = dst_price, primary_price

            # Gross profit (before bridge fees)
            price_spread = abs(dst_price - primary_price) / primary_price
            gross_profit = trade_amount * price_spread

            # Costs
            bridge_fee = bridge.fee
            swap_fee = trade_amount * 0.003  # 0.3% DEX fee on each side
            total_fees = bridge_fee + swap_fee * 2

            # Gas (2 swaps + bridge call)
            gas_units = 2 * SWAP_GAS_BASE + 200_000
            usdc_token = Token("USDC")
            gas_cost = self._estimate_gas_cost(gas_units, usdc_token)

            net_profit = gross_profit - total_fees - gas_cost

            # Risk adjustment for bridge latency and failure
            risk_multiplier = bridge.reliability_score * (1.0 - bridge.estimated_time_seconds / 3600.0)
            adjusted_pnl = net_profit * risk_multiplier

            if adjusted_pnl > best_pnl and net_profit > 0:
                best_pnl = adjusted_pnl
                best_opp = Opportunity(
                    strategy_name="cross_chain",
                    path=[],
                    profit_token=usdc_token,
                    gross_profit=gross_profit,
                    total_fees=total_fees,
                    gas_cost=gas_cost,
                    net_profit=adjusted_pnl,
                    capital_required=trade_amount,
                    gas_estimate=gas_units,
                    confidence=min(1.0, price_spread / 0.01),
                    risk_score=0.5,  # bridge risk
                    metadata={
                        "token": token_sym,
                        "buy_chain": buy_chain,
                        "sell_chain": sell_chain,
                        "bridge": bridge.bridge_name,
                        "price_spread_pct": price_spread,
                        "bridge_fee": bridge_fee,
                        "estimated_time_s": bridge.estimated_time_seconds,
                        "reliability": bridge.reliability_score,
                    },
                )

        return best_opp


# ===========================================================================
# Strategy 10: Lending Rate Arbitrage (Carry Trade)
# ===========================================================================

@dataclass
class LendingMarket:
    """A lending/borrowing market on a protocol."""
    protocol: str          # "aave", "compound", "spark", "morpho", "marginfi"
    chain: str
    token: str
    deposit_apr: float     # annual percentage rate for depositors
    borrow_apr: float     # annual percentage rate for borrowers
    utilization: float     # 0.0 to 1.0
    total_deposits: float
    total_borrows: float
    collateral_factor: float  # max LTV
    liquidation_threshold: float

    @property
    def rate_spread(self) -> float:
        """Deposit rate - borrow rate (negative means you pay)."""
        return self.deposit_apr - self.borrow_apr

    @property
    def net_apr(self) -> float:
        """Net APR after accounting for protocol fees and utilization."""
        # Effective borrow rate depends on utilization
        if self.utilization > 0.9:
            # Rates spike when utilization is high — can create transient arb
            return self.deposit_apr - self.borrow_apr * (1.0 + self.utilization * 0.5)
        return self.rate_spread


class LendingRateArbitrage(Strategy):
    """
    Borrow from a low-rate protocol, lend at a higher-rate protocol.

    This is a directional carry trade, not pure arb — you earn the
    rate spread. The risk is that rates change.

    Where the opportunity exists:
    - Aave vs Compound vs Spark (same asset, different utilization curves)
    - Morpho Blue (optimised Aave) vs raw Aave
    - Protocol-specific promotions (extra incentives on new markets)
    - Utilization spikes (temporary rate dislocation after large liquidations)

    Why it's less saturated:
    - Capital intensive (need collateral)
    - Rate moves can eliminate the spread
    - Requires monitoring multiple lending protocols
    - Not atomic — position management overhead
    """

    def __init__(
        self,
        lending_markets: Optional[List[LendingMarket]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.lending_markets = lending_markets or self._default_markets()

    def _default_markets(self) -> List[LendingMarket]:
        """Generate realistic lending market data."""
        markets = []

        # USDC markets across protocols (different utilizations → different rates)
        base_deposit = 0.04  # 4% base
        base_borrow = 0.06   # 6% base

        protocols = [
            ("aave", 0.85),    # Aave V3: high utilization → high borrow rate
            ("compound", 0.60), # Compound: moderate utilization
            ("spark", 0.70),   # Spark: similar to Aave but different params
            ("morpho", 0.75),  # Morpho Blue: optimised, tighter spreads
        ]

        for token in ["USDC", "USDT", "DAI"]:
            for protocol_name, util in protocols:
                # Deposit rate = borrow_rate * utilization * (1 - protocol_fee)
                deposit = base_borrow * util * 0.85
                borrow = base_borrow * (1.0 + util * 0.3)  # rate curve
                markets.append(LendingMarket(
                    protocol=protocol_name,
                    chain="ethereum",
                    token=token,
                    deposit_apr=deposit,
                    borrow_apr=borrow,
                    utilization=util,
                    total_deposits=500_000_000 * (1.0 + util),
                    total_borrows=500_000_000 * util,
                    collateral_factor=0.80,
                    liquidation_threshold=0.85,
                ))

        # Add some dislocated markets (opportunities!)
        markets.append(LendingMarket(
            protocol="aave", chain="arbitrum", token="USDC",
            deposit_apr=0.065, borrow_apr=0.05,  # inverted! arb opportunity
            utilization=0.95, total_deposits=100_000_000,
            total_borrows=95_000_000,
            collateral_factor=0.80, liquidation_threshold=0.85,
        ))

        return markets

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for token_sym in ["USDC", "USDT", "DAI"]:
            opp = self._find_rate_dislocation(token_sym)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _find_rate_dislocation(
        self, token_sym: str
    ) -> Optional[Opportunity]:
        """Find pairs of lending markets with exploitable rate spreads."""

        # Filter markets for this token
        token_markets = [
            m for m in self.lending_markets if m.token == token_sym
        ]
        if len(token_markets) < 2:
            return None

        best_opp = None
        best_pnl = 0.0

        for i in range(len(token_markets)):
            for j in range(len(token_markets)):
                if i == j:
                    continue

                borrow_market = token_markets[i]
                lend_market = token_markets[j]

                # We want: borrow at LOW rate, lend at HIGH rate
                rate_spread = lend_market.deposit_apr - borrow_market.borrow_apr
                if rate_spread <= 0.001:  # < 0.1% spread, not worth it
                    continue

                # Position sizing
                max_borrow = borrow_market.total_deposits * 0.01  # 1% of deposits
                position_size = min(max_borrow, 1_000_000.0)

                # Calculate per-block return (Ethereum ~12s blocks)
                blocks_per_year = 365.25 * 24 * 3600 / 12
                per_block_rate = rate_spread / blocks_per_year

                # Profit for holding position for ~100 blocks (~20 minutes)
                hold_blocks = 100
                gross_profit = position_size * per_block_rate * hold_blocks

                # Costs
                gas_units = 200_000  # supply + borrow txs
                usdc_token = Token("USDC")
                gas_cost = self._estimate_gas_cost(gas_units, usdc_token)

                # Flash loan fee if using leverage
                flash_fee = 0.0
                if position_size > 100_000:
                    flash_fee = position_size * 0.0005  # Aave flash loan fee

                net_profit = gross_profit - gas_cost - flash_fee

                if net_profit > best_pnl:
                    best_pnl = net_profit
                    best_opp = Opportunity(
                        strategy_name="lending_rate",
                        path=[],
                        profit_token=usdc_token,
                        gross_profit=gross_profit,
                        total_fees=0.0,
                        gas_cost=gas_cost,
                        flash_loan_fee=flash_fee,
                        net_profit=net_profit,
                        capital_required=position_size * 0.2,  # collateral needed
                        uses_flash_loan=position_size > 100_000,
                        gas_estimate=gas_units,
                        confidence=min(1.0, rate_spread / 0.02),
                        risk_score=0.3,  # low — rates are somewhat predictable
                        metadata={
                            "token": token_sym,
                            "borrow_protocol": borrow_market.protocol,
                            "lend_protocol": lend_market.protocol,
                            "borrow_chain": borrow_market.chain,
                            "lend_chain": lend_market.chain,
                            "rate_spread_apr": rate_spread,
                            "position_size": position_size,
                            "hold_blocks": hold_blocks,
                            "borrow_util": borrow_market.utilization,
                            "lend_util": lend_market.utilization,
                        },
                    )

        return best_opp


# ===========================================================================
# Strategy 11: Intent / CoW Order Arbitrage
# ===========================================================================

@dataclass
class IntentOrder:
    """An off-chain intent/order from a solver network."""
    order_id: str
    solver: str               # "cow_protocol", "uniswapx", "1inch_limit"
    token_in: str
    token_out: str
    amount_in: float
    min_amount_out: float      # limit price
    deadline: float           # timestamp
    partially_fillable: bool
    submitted_at: float

    @property
    def limit_price(self) -> float:
        if self.amount_in <= 0:
            return 0.0
        return self.min_amount_out / self.amount_in


class IntentOrderArbitrage(Strategy):
    """
    Monitor off-chain intent/co-order flows for mispricing.

    Intent-based DEXs (CoW Protocol, UniswapX, 1inch Limit Orders)
    settle orders off-chain through solvers. These orders often have
    slack (worse limit than market price) or are partially fillable.

    Opportunities:
    1. Fill stale limit orders at their limit price, sell at market
    2. Provide liquidity to batch auctions at favorable clearing prices
    3. Cross-solver arb: same token, different solver, different clearing price

    Why it's less saturated:
    - Off-chain orderflow is fragmented (multiple solvers)
    - Requires integration with solver APIs
    - Stale orders are time-sensitive but not block-critical
    - Intent-based DEXs are growing fast but bot ecosystem is nascent
    """

    def __init__(
        self,
        intent_orders: Optional[List[IntentOrder]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.intent_orders = intent_orders or self._default_orders()

    def _default_orders(self) -> List[IntentOrder]:
        """Generate sample intent orders with some stale/mispriced ones."""
        orders = []
        import time
        now = time.time()

        # Well-priced orders (no arb)
        for i in range(5):
            orders.append(IntentOrder(
                order_id=f"order_good_{i}",
                solver="cow_protocol",
                token_in="WETH",
                token_out="USDC",
                amount_in=1.0,
                min_amount_out=2500.0,  # fair price
                deadline=now + 300,
                partially_fillable=False,
                submitted_at=now - 10,
            ))

        # Stale orders (limit price above market — arb opportunity!)
        for i in range(3):
            orders.append(IntentOrder(
                order_id=f"order_stale_{i}",
                solver="uniswapx",
                token_in="WETH",
                token_out="USDC",
                amount_in=1.0,
                min_amount_out=2600.0,  # above market — buy cheap from them
                deadline=now + 600,
                partially_fillable=True,
                submitted_at=now - 300,  # 5 min old, might be stale
            ))

        # 1inch limit orders
        for i in range(2):
            orders.append(IntentOrder(
                order_id=f"order_1inch_{i}",
                solver="1inch_limit",
                token_in="USDC",
                token_out="WETH",
                amount_in=5000.0,
                min_amount_out=2.1,  # slightly above market
                deadline=now + 1200,
                partially_fillable=True,
                submitted_at=now - 60,
            ))

        return orders

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for order in self.intent_orders:
            opp = self._evaluate_intent(market, order)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_intent(
        self, market: Market, order: IntentOrder
    ) -> Optional[Opportunity]:
        """Evaluate an intent order for arbitrage opportunity."""

        # Get current market price for the pair
        try:
            market_price = market.price_between(
                order.token_out, order.token_in
            )
            if market_price <= 0:
                return None
        except Exception:
            return None

        # Invert: what's the market rate for token_in → token_out?
        if market_price > 0:
            market_rate = 1.0 / market_price
        else:
            return None

        # Compare order's limit price to market price
        order_price = order.limit_price
        price_diff = abs(order_price - market_rate) / market_rate

        if price_diff < 0.003:  # < 0.3% not worth it
            return None

        # Determine direction
        # If order wants to sell token_in at limit_price > market_rate,
        # we can buy from them cheap and sell at market
        if order_price > market_rate:
            # We fill their order (buy token_out at their limit)
            profit_per_unit = order_price - market_rate
            amount = order.amount_in
            gross_profit = amount * profit_per_unit

            # We receive token_out from the order, sell at market
            token_out = market.token_registry.get(order.token_out, Token(order.token_out))
        else:
            # Order is buying at below-market — not useful for us as counterparty
            return None

        # Staleness bonus: older orders more likely to have slack
        import time
        age_seconds = time.time() - order.submitted_at
        staleness_bonus = min(1.0, age_seconds / 600.0) * 0.005  # up to 0.5%

        # Costs
        gas_units = 180_000  # solver settlement gas
        gas_cost = self._estimate_gas_cost(gas_units, Token(order.token_in))

        # Solver fee (some intent protocols charge solver fees)
        solver_fee = amount * 0.0005  # 0.05% typical solver fee

        net_profit = gross_profit + (amount * staleness_bonus) - gas_cost - solver_fee

        if net_profit <= 0:
            return None

        return Opportunity(
            strategy_name="intent_arb",
            path=[],
            profit_token=Token(order.token_in),
            gross_profit=gross_profit,
            total_fees=solver_fee,
            gas_cost=gas_cost,
            net_profit=net_profit,
            capital_required=amount,
            gas_estimate=gas_units,
            confidence=min(1.0, price_diff / 0.01) * min(1.0, age_seconds / 60.0),
            risk_score=0.4,
            metadata={
                "order_id": order.order_id,
                "solver": order.solver,
                "token_in": order.token_in,
                "token_out": order.token_out,
                "order_price": order_price,
                "market_rate": market_rate,
                "price_diff_pct": price_diff,
                "age_seconds": age_seconds,
                "staleness_bonus_pct": staleness_bonus,
            },
        )


# ===========================================================================
# Strategy 12: Vault / NAV Arbitrage
# ===========================================================================

@dataclass
class VaultPosition:
    """A vault (Yearn, Eigenpie, Arrakis, etc.)."""
    vault_name: str
    protocol: str
    vault_token: str        # e.g., "yvUSDC", "weETH"
    underlying_token: str  # e.g., "USDC", "ETH"
    share_price: float      # 1 vault share = X underlying
    nav: float              # actual underlying value per share
    total_tvl: float
    exit_fee_bps: int
    withdrawal_delay_seconds: float

    @property
    def premium(self) -> float:
        """Premium/discount of share price vs NAV."""
        if self.nav <= 0:
            return 0.0
        return (self.share_price - self.nav) / self.nav

    @property
    def is_discounted(self) -> bool:
        return self.share_price < self.nav


class VaultNavArbitrage(Strategy):
    """
    Exploit premium/discount of vault shares vs their underlying NAV.

    Vault shares (yvTokens, weETH, rsETH, etc.) can trade at a premium
    or discount to their actual underlying value due to:
    - Withdrawal queues (EigenLayer restaking queues)
    - Fee accrual timing
    - Liquidity asymmetry
    - Market sentiment

    Opportunities:
    1. Buy discounted vault shares, redeem for underlying (instant profit)
    2. Buy underlying, mint vault shares at premium, sell shares
    3. Provide liquidity in vault token pairs when spreads are wide

    Why it's less saturated:
    - Requires deep knowledge of each vault's redemption mechanism
    - Some redemptions have delays (hours to days)
    - Vault accounting is complex
    - Fewer bots track vault vs NAV discrepancies
    """

    def __init__(
        self,
        vaults: Optional[List[VaultPosition]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.vaults = vaults or self._default_vaults()

    def _default_vaults(self) -> List[VaultPosition]:
        """Generate vault positions with realistic premiums/discounts."""
        import random
        rng = random.Random(42)

        vaults = [
            VaultPosition(
                vault_name="yvUSDC-Aave",
                protocol="yearn",
                vault_token="yvUSDC",
                underlying_token="USDC",
                share_price=1.02 + rng.uniform(-0.02, 0.02),
                nav=1.02,
                total_tvl=50_000_000,
                exit_fee_bps=0,
                withdrawal_delay_seconds=0,  # instant
            ),
            VaultPosition(
                vault_name="weETH",
                protocol="etherfi",
                vault_token="weETH",
                underlying_token="WETH",
                share_price=1.005 + rng.uniform(-0.008, 0.008),
                nav=1.005,
                total_tvl=800_000_000,  # $800M TVL
                exit_fee_bps=0,
                withdrawal_delay_seconds=0,
            ),
            VaultPosition(
                vault_name="rsETH-RocketPool",
                protocol="rocketpool",
                vault_token="rsETH",
                underlying_token="WETH",
                share_price=1.01 + rng.uniform(-0.015, 0.015),
                nav=1.01,
                total_tvl=2_000_000_000,
                exit_fee_bps=5,
                withdrawal_delay_seconds=86400,  # 24h queue
            ),
            VaultPosition(
                vault_name="Eigenpie-weETH",
                protocol="eigenpie",
                vault_token="EPI-weETH",
                underlying_token="weETH",
                share_price=1.03 + rng.uniform(-0.03, 0.03),
                nav=1.03,
                total_tvl=300_000_000,
                exit_fee_bps=10,
                withdrawal_delay_seconds=259200,  # 3-day queue
            ),
            VaultPosition(
                vault_name="Arrakis-WETH-USDC-01",
                protocol="arrakis",
                vault_token="arrakis-WETH-USDC",
                underlying_token="WETH",
                share_price=2500.0 + rng.uniform(-50, 50),
                nav=2500.0,
                total_tvl=10_000_000,
                exit_fee_bps=0,
                withdrawal_delay_seconds=0,
            ),
        ]
        return vaults

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for vault in self.vaults:
            opp = self._evaluate_vault(market, vault)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_vault(
        self, market: Market, vault: VaultPosition
    ) -> Optional[Opportunity]:
        """Evaluate a vault for NAV discrepancy."""

        premium = vault.premium
        abs_premium = abs(premium)

        if abs_premium < 0.005:  # < 0.5% premium/discount
            return None

        profit_token = market.token_registry.get(
            vault.underlying_token,
            Token(vault.underlying_token)
        )

        # Position sizing based on TVL
        position_size = min(vault.total_tvl * 0.001, 1_000_000.0)

        if vault.is_discounted:
            # Buy vault shares at discount, redeem for full NAV
            shares_to_buy = position_size / vault.share_price
            underlying_received = shares_to_buy * vault.nav
            gross_profit = underlying_received - position_size
        else:
            # Vault at premium — we can't easily exploit (need to mint shares)
            # Skip unless we can create shares somehow
            return None

        if gross_profit <= 0:
            return None

        # Costs
        gas_units = 250_000  # deposit + withdraw
        gas_cost = self._estimate_gas_cost(gas_units, profit_token)
        exit_fee = position_size * vault.exit_fee_bps / 10_000

        # Time cost: opportunity cost of capital locked during withdrawal
        time_cost = 0.0
        if vault.withdrawal_delay_seconds > 0:
            # Capital locked for N seconds → can't use elsewhere
            # Model as: position_size * risk_free_rate * lock_time
            risk_free_apr = 0.04
            lock_years = vault.withdrawal_delay_seconds / (365.25 * 24 * 3600)
            time_cost = position_size * risk_free_apr * lock_years

        net_profit = gross_profit - gas_cost - exit_fee - time_cost

        if net_profit <= 0:
            return None

        return Opportunity(
            strategy_name="vault_nav",
            path=[],
            profit_token=profit_token,
            gross_profit=gross_profit,
            total_fees=exit_fee,
            gas_cost=gas_cost,
            net_profit=net_profit,
            capital_required=position_size,
            gas_estimate=gas_units,
            confidence=min(1.0, abs_premium / 0.02),
            risk_score=0.5 if vault.withdrawal_delay_seconds > 0 else 0.2,
            metadata={
                "vault": vault.vault_name,
                "protocol": vault.protocol,
                "vault_token": vault.vault_token,
                "underlying": vault.underlying_token,
                "share_price": vault.share_price,
                "nav": vault.nav,
                "premium_pct": premium * 100,
                "exit_fee_bps": vault.exit_fee_bps,
                "withdrawal_delay_s": vault.withdrawal_delay_seconds,
            },
        )


# ===========================================================================
# Strategy 13: Liquid Staking Yield Loop (Leveraged Staking)
# ===========================================================================

@dataclass
class StakingPool:
    """A liquid staking derivative (LSD) pool."""
    name: str               # "lido", "rocketpool", "etherfi", "frax"
    lst_token: str          # "stETH", "rETH", "weETH", "sfrxETH"
    peg_token: str          # "WETH"
    exchange_rate: float    # 1 stETH = X WETH (should be ~1.0 + APY)
    apr: float              # annual percentage yield
    tvl: float
    mint_fee_bps: int
    redeem_fee_bps: int
    redeem_delay_seconds: float

    @property
    def premium(self) -> float:
        """Premium of LST over ETH."""
        return self.exchange_rate - 1.0


class LiquidStakingLoop(Strategy):
    """
    Leveraged staking yield via LST looping.

    Strategy:
    1. Stake ETH → get stETH (or rETH, weETH, etc.)
    2. Use stETH as collateral on Aave to borrow more ETH
    3. Stake the borrowed ETH → get more stETH
    4. Repeat for leverage

    Profit = staking_yield - borrow_rate - gas_costs - fees

    The loop amplifies the staking yield by leverage. With 3 loops
    at 80% LTV, you effectively stake ~3x your capital.

    Risk factors:
    - Depeg: LST could lose peg during stress (stETH briefly dropped to 0.95 ETH)
    - Liquidation: if ETH drops, collateral (stETH) drops too → cascading
    - Rate changes: Aave borrow rate could exceed staking yield

    Why it's less saturated:
    - Complex risk management required
    - Capital intensive
    - Needs monitoring of multiple parameters
    - Depeg risk scares simple bots away
    """

    def __init__(
        self,
        staking_pools: Optional[List[StakingPool]] = None,
        lending_markets: Optional[List[LendingMarket]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.staking_pools = staking_pools or self._default_staking_pools()
        self.lending_markets = lending_markets or []

    def _default_staking_pools(self) -> List[StakingPool]:
        """Generate realistic LSD pool data."""
        import random
        rng = random.Random(99)

        return [
            StakingPool(
                name="lido",
                lst_token="stETH",
                peg_token="WETH",
                exchange_rate=1.02 + rng.uniform(-0.005, 0.005),
                apr=0.035,   # 3.5% staking yield
                tvl=15_000_000_000,
                mint_fee_bps=0,
                redeem_fee_bps=0,
                redeem_delay_seconds=0,  # instant on Curve
            ),
            StakingPool(
                name="rocketpool",
                lst_token="rETH",
                peg_token="WETH",
                exchange_rate=1.035 + rng.uniform(-0.005, 0.005),
                apr=0.035,   # ~3.5%
                tvl=3_000_000_000,
                mint_fee_bps=0,
                redeem_fee_bps=0,
                redeem_delay_seconds=0,
            ),
            StakingPool(
                name="etherfi",
                lst_token="weETH",
                peg_token="WETH",
                exchange_rate=1.03 + rng.uniform(-0.005, 0.005),
                apr=0.035,   # ~3.5%
                tvl=800_000_000,
                mint_fee_bps=0,
                redeem_fee_bps=0,
                redeem_delay_seconds=0,
            ),
        ]

    def scan(self, market: Market) -> List[Opportunity]:
        opportunities = []

        for pool in self.staking_pools:
            opp = self._evaluate_loop(market, pool)
            if opp:
                opportunities.append(opp)

        return opportunities

    def _evaluate_loop(
        self, market: Market, pool: StakingPool
    ) -> Optional[Opportunity]:
        """Evaluate a leveraged staking loop opportunity."""

        weth_token = Token("WETH")

        # Staking yield per block
        blocks_per_year = 365.25 * 24 * 3600 / 12
        staking_yield_per_block = pool.apr / blocks_per_year

        # Borrow cost per block (Aave WETH borrow rate)
        # In production, fetch from Aave subgraph
        # We model ~4% borrow rate
        borrow_apr = 0.04
        borrow_cost_per_block = borrow_apr / blocks_per_year

        # Net yield per block per unit of capital
        net_yield_per_block = staking_yield_per_block - borrow_cost_per_block

        if net_yield_per_block <= 0:
            return None  # Not profitable at current rates

        # Calculate leveraged yield through N loops
        capital = 10.0  # 10 ETH base
        ltv = 0.75      # 75% LTV on Aave (safe for ETH)
        max_loops = 5

        total_exposure = 0.0
        total_collateral = capital
        total_borrowed = 0.0
        loop_costs_gas = 0.0

        for loop in range(max_loops):
            # Stake current collateral
            staked = total_collateral
            if staked <= 0.01:
                break

            # Borrow against staked LST
            borrow_amount = staked * pool.exchange_rate * ltv
            total_borrowed += borrow_amount

            # Convert borrowed to ETH (assuming 1:1 for simulation)
            new_capital = borrow_amount
            total_collateral = new_capital

            # Gas for this loop
            loop_costs_gas += 400_000  # stake + deposit + borrow

        total_exposure = capital + total_borrowed

        # Effective leverage
        leverage = total_exposure / capital if capital > 0 else 0

        # Hold for N blocks
        hold_blocks = 100  # ~20 minutes
        gross_profit = total_exposure * net_yield_per_block * hold_blocks

        # Gas costs
        gas_cost = self._estimate_gas_cost(loop_costs_gas, weth_token)

        # Depreciation cost: LST might lose peg slightly
        # Model as: premium erosion over hold time
        premium_erosion = pool.premium * (hold_blocks / blocks_per_year)
        depeg_cost = total_exposure * max(0, -premium_erosion)

        # Liquidation risk: if ETH drops, LTV increases
        # Model as probability-weighted loss
        liquidation_risk_cost = total_exposure * 0.001  # 0.1% risk premium

        net_profit = gross_profit - gas_cost - depeg_cost - liquidation_risk_cost

        if net_profit <= 0:
            return None

        return Opportunity(
            strategy_name="liquid_staking",
            path=[],
            profit_token=weth_token,
            gross_profit=gross_profit,
            total_fees=0.0,
            gas_cost=gas_cost,
            net_profit=net_profit,
            capital_required=capital,
            gas_estimate=loop_costs_gas,
            confidence=min(1.0, (net_yield_per_block * blocks_per_year * 100) / 0.01),
            risk_score=0.6,  # moderate — depeg + liquidation risk
            metadata={
                "lst": pool.lst_token,
                "pool": pool.name,
                "staking_apr": pool.apr,
                "borrow_apr": borrow_apr,
                "net_apr": net_yield_per_block * blocks_per_year,
                "leverage": leverage,
                "loops": max_loops,
                "total_exposure_eth": total_exposure,
                "capital_eth": capital,
                "hold_blocks": hold_blocks,
                "depeg_risk": depeg_cost,
            },
        )


# ===========================================================================
# Updated Strategy Registry (with all 13 strategies)
# ===========================================================================

def create_enhanced_registry(
    gas_price_gwei: float = 30.0,
    eth_price_usd: float = 2000.0,
    pending_txs: List[Dict] = None,
    pending_swaps: List[Dict] = None,
    lending_markets: List[LendingMarket] = None,
    intent_orders: List[IntentOrder] = None,
) -> "StrategyRegistry":
    """
    Create an enhanced registry with all 13 strategies.

    This replaces the basic StrategyRegistry._register_defaults()
    to include the 6 new advanced strategies.
    """
    from src.strategies.engines import (
        CrossDexArbitrage, TriangularArbitrage, FlashLoanArbitrage,
        LiquidationHunter, SandwichAttack, FundingRateArbitrage,
        MEVBundleComposer, StrategyRegistry,
    )

    registry = StrategyRegistry(
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )

    # Add advanced strategies
    registry.strategies["jit_liquidity"] = JitLiquidity(
        pending_swaps=pending_swaps or [],
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )
    registry.strategies["cross_chain"] = CrossChainArbitrage(
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )
    registry.strategies["lending_rate"] = LendingRateArbitrage(
        lending_markets=lending_markets or [],
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )
    registry.strategies["intent_arb"] = IntentOrderArbitrage(
        intent_orders=intent_orders or [],
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )
    registry.strategies["vault_nav"] = VaultNavArbitrage(
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )
    registry.strategies["liquid_staking"] = LiquidStakingLoop(
        gas_price_gwei=gas_price_gwei,
        eth_price_usd=eth_price_usd,
    )

    # Update the summary vector to include all 13 strategies
    _original_summary = registry.summary_vector

    def enhanced_summary_vector(results):
        """Extended summary with all 13 strategies (39 features)."""
        vec = []
        all_names = [
            "cross_dex", "triangular", "flash_loan", "liquidation",
            "sandwich", "funding_rate", "mev_bundle",
            "jit_liquidity", "cross_chain", "lending_rate",
            "intent_arb", "vault_nav", "liquid_staking",
        ]
        for name in all_names:
            opps = results.get(name, [])
            count = len(opps)
            best_pnl = max((o.net_profit for o in opps), default=0.0)
            best_roi = max((o.roi for o in opps), default=0.0)
            vec.extend([count, best_pnl, best_roi])
        return vec

    registry.summary_vector = enhanced_summary_vector

    return registry
