"""
FlashMind — Market Generator
============================
Generates realistic market states for RL training.

Usage:
    from src.amm.market_gen import MarketGenerator

    gen = MarketGenerator(seed=42)
    market = gen.generate_market()

Each call creates a fresh Market with randomized reserves, prices, and pool
configurations drawn from realistic on-chain distributions.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional, Tuple

from .constants import (
    ALL_PROTOCOLS, MAJOR_TOKENS, STABLECOINS,
    V2_FEE_BPS, V3_FEE_TIERS_BPS,
)
from .pools import (
    AMMPool, BalancerV2Pool, CurvePool, Market,
    Token, UniswapV2Pool, UniswapV3Pool, create_pool,
)


# ---------------------------------------------------------------------------
# Realistic initial price ranges (token → approximate USD value)
# ---------------------------------------------------------------------------
PRICE_RANGES_USD: Dict[str, Tuple[float, float]] = {
    "WETH":  (1500.0, 4500.0),
    "WBTC":  (25000.0, 75000.0),
    "USDT":  (0.99, 1.01),
    "USDC":  (0.99, 1.01),
    "DAI":   (0.98, 1.02),
    "ARB":   (0.5, 3.0),
    "OP":    (0.5, 4.0),
    "BNB":   (200.0, 700.0),
    "FRAX":  (0.99, 1.01),
    "LUSD":  (0.99, 1.01),
    "CRV":   (0.2, 2.0),
    "LINK":  (5.0, 30.0),
    "UNI":   (3.0, 20.0),
    "AAVE":  (50.0, 200.0),
    "MKR":   (500.0, 3000.0),
    "SNX":   (1.0, 10.0),
}

# Realistic reserve ranges (in token units) per pool type
RESERVE_RANGES: Dict[str, Tuple[float, float]] = {
    # (min_reserve, max_reserve) for the MAJOR token in the pair
    "major_major":   (100.0, 10000.0),     # WETH/WBTC
    "major_stable":  (500_000.0, 50_000_000.0),  # WETH/USDC
    "stable_stable": (1_000_000.0, 200_000_000.0),  # USDC/USDT
}

# How many pools per protocol to create (roughly)
POOL_COUNTS: Dict[str, Tuple[int, int]] = {
    "uniswap_v2":  (8, 20),
    "uniswap_v3":  (8, 20),
    "sushiswap_v2": (3, 8),
    "curve_v1":    (2, 5),
    "balancer_v2": (2, 5),
    "pancake_v2":  (3, 8),
    "pancake_v3":  (2, 5),
}


class MarketGenerator:
    """
    Procedural market generator for RL training.

    Generates pools with realistic reserves, prices, and fee structures.
    Every call to ``generate_market()`` returns a fresh, independent Market.
    """

    def __init__(
        self,
        seed: Optional[int] = None,
        protocols: Optional[List[str]] = None,
        num_extra_tokens: int = 5,
        volatility: float = 0.02,
    ):
        """
        Args:
            seed: Random seed for reproducibility.
            protocols: Which protocols to include (default: all).
            num_extra_tokens: How many additional tokens beyond MAJOR_TOKENS.
            volatility: Price jitter factor for creating initial imbalances.
        """
        self.rng = random.Random(seed)
        self.protocols = protocols or ALL_PROTOCOLS
        self.volatility = volatility

        # Token universe
        self.tokens: Dict[str, Token] = {}
        for sym in MAJOR_TOKENS:
            self.tokens[sym] = Token(sym)

        # Extra tokens for diversity
        extra_names = list(PRICE_RANGES_USD.keys())
        extra_names = [n for n in extra_names if n not in self.tokens]
        for name in extra_names[:num_extra_tokens]:
            self.tokens[name] = Token(name)

    def generate_market(
        self,
        num_pools: Optional[int] = None,
    ) -> Market:
        """
        Generate a complete Market instance.

        Args:
            num_pools: Override total pool count. If None, uses protocol defaults.
        """
        market = Market()

        # Choose token pairs to create pools for
        pairs = self._select_pairs()

        pools_created = 0
        for protocol in self.protocols:
            count = POOL_COUNTS.get(protocol, (2, 6))
            n = self.rng.randint(count[0], count[1])
            if num_pools is not None:
                # Distribute proportionally
                remaining = num_pools - pools_created
                remaining_protocols = len(self.protocols) - self.protocols.index(protocol)
                n = min(n, max(0, remaining // max(remaining_protocols, 1)))

            for _ in range(n):
                pair = self.rng.choice(pairs)
                pool = self._create_pool_for_pair(protocol, pair)
                if pool:
                    market.add_pool(pool)
                    pools_created += 1

                if num_pools is not None and pools_created >= num_pools:
                    break

            if num_pools is not None and pools_created >= num_pools:
                break

        # Apply initial price imbalances (volatility)
        self._apply_imbalances(market)

        return market

    def _select_pairs(self) -> List[Tuple[str, str]]:
        """Select diverse token pairs covering all strategy types."""
        pairs = []

        stablecoins = [s for s in STABLECOINS if s in self.tokens]
        majors = [t for t in self.tokens if t not in stablecoins]

        # Stable-stable pairs (for Curve, triangular arb via stablecoins)
        for i in range(len(stablecoins)):
            for j in range(i + 1, len(stablecoins)):
                pairs.append((stablecoins[i], stablecoins[j]))

        # Major-stable pairs (most liquid, most arb opportunities)
        for m in majors[:6]:
            for s in stablecoins[:3]:
                pairs.append((m, s))

        # Major-major pairs (for cross-DEX arb, triangular)
        for i in range(len(majors[:6])):
            for j in range(i + 1, len(majors[:6])):
                pairs.append((majors[i], majors[j]))

        return pairs

    def _create_pool_for_pair(
        self, protocol: str, pair: Tuple[str, str]
    ) -> Optional[AMMPool]:
        """Create a single pool with realistic parameters."""
        sym_a, sym_b = pair
        token_a, token_b = self.tokens[sym_a], self.tokens[sym_b]

        # Determine reserve range
        a_is_stable = sym_a in STABLECOINS
        b_is_stable = sym_b in STABLECOINS

        if a_is_stable and b_is_stable:
            category = "stable_stable"
        elif a_is_stable or b_is_stable:
            category = "major_stable"
        else:
            category = "major_major"

        # Generate base price for token_b in terms of token_a
        price_a_usd = self._sample_price(sym_a)
        price_b_usd = self._sample_price(sym_b)
        price_ratio = price_a_usd / price_b_usd

        # Generate reserves
        r_min, r_max = RESERVE_RANGES[category]
        reserve_base = self.rng.uniform(r_min, r_max)

        # Major token gets the reserve_base, stable/quote gets derived amount
        if a_is_stable:
            reserve_a = reserve_base
            reserve_b = reserve_base / price_ratio
        else:
            reserve_a = reserve_base
            reserve_b = reserve_base * price_ratio

        # Add some randomness
        reserve_a *= self.rng.uniform(0.8, 1.2)
        reserve_b *= self.rng.uniform(0.8, 1.2)

        # Create pool
        address = f"0x{self.rng.randbytes(20).hex()}"

        try:
            if protocol in ("uniswap_v2", "sushiswap_v2", "pancake_v2"):
                fee = V2_FEE_BPS
                return UniswapV2Pool(
                    token_a, token_b, reserve_a, reserve_b,
                    fee_bps=fee, protocol=protocol, address=address,
                )

            elif protocol in ("uniswap_v3", "pancake_v3", "spirit_v3"):
                fee = self.rng.choice(V3_FEE_TIERS_BPS)
                sqrt_price = math.sqrt(reserve_b / reserve_a) * (2 ** 96)
                liquidity = math.sqrt(reserve_a * reserve_b)
                return UniswapV3Pool(
                    token_a, token_b, liquidity, sqrt_price,
                    fee_bps=fee, protocol=protocol, address=address,
                )

            elif protocol == "curve_v1":
                # Curve mainly for stable-stable, occasionally major-stable
                if not (a_is_stable and b_is_stable):
                    return None
                amplification = self.rng.choice([50, 100, 200, 500, 1000, 2000])
                return CurvePool(
                    (token_a, token_b),
                    {sym_a: reserve_a, sym_b: reserve_b},
                    amplification=amplification,
                    fee_bps=4, protocol=protocol, address=address,
                )

            elif protocol == "balancer_v2":
                # Balancer: sometimes 80/20 or 60/40 weights
                if self.rng.random() < 0.5:
                    w_a = self.rng.choice([0.2, 0.3, 0.4])
                    w_b = 1.0 - w_a
                else:
                    w_a, w_b = 0.5, 0.5
                return BalancerV2Pool(
                    (token_a, token_b),
                    {sym_a: reserve_a, sym_b: reserve_b},
                    weights={sym_a: w_a, sym_b: w_b},
                    fee_bps=self.rng.choice([10, 30, 100]),
                    protocol=protocol, address=address,
                )

        except (ValueError, ZeroDivisionError):
            return None

        return None

    def _sample_price(self, symbol: str) -> float:
        """Sample a realistic price for a token."""
        if symbol in PRICE_RANGES_USD:
            lo, hi = PRICE_RANGES_USD[symbol]
            # Log-uniform sampling for better coverage
            log_lo = math.log(lo)
            log_hi = math.log(hi)
            return math.exp(self.rng.uniform(log_lo, log_hi))
        return self.rng.uniform(0.1, 100.0)

    def _apply_imbalances(self, market: Market, probability: float = 0.5):
        """
        Randomly create price imbalances across pools.

        This is CRITICAL for RL training — the agent needs to learn to
        detect and exploit these. Without imbalances, there's nothing to
        arbitrage and the agent learns nothing useful.

        Imbalances simulate:
        - Recent large swaps that haven't been arb'd yet
        - Oracle lag between DEXes
        - Asymmetric liquidity provision
        """
        import math

        for pool in market.pools.values():
            if self.rng.random() > probability:
                continue

            imbalance_factor = self.rng.uniform(0.7, 1.3) ** (1 if self.rng.random() > 0.5 else -1)

            if isinstance(pool, UniswapV2Pool):
                # Shift reserves asymmetrically
                if self.rng.random() > 0.5:
                    pool._reserve0 *= imbalance_factor
                    pool._reserve1 /= imbalance_factor
                else:
                    pool._reserve0 /= imbalance_factor
                    pool._reserve1 *= imbalance_factor

            elif isinstance(pool, UniswapV3Pool):
                # Shift the sqrt price
                pool.sqrt_price_x96 *= math.sqrt(imbalance_factor)
                pool._compute_virtual_reserves()

            elif isinstance(pool, CurvePool):
                for sym in pool._reserves:
                    pool._reserves[sym] *= self.rng.uniform(0.95, 1.05)

            elif isinstance(pool, BalancerV2Pool):
                for sym in pool._reserves:
                    pool._reserves[sym] *= self.rng.uniform(0.95, 1.05)


# Need math import at top level for _create_pool_for_pair
import math
