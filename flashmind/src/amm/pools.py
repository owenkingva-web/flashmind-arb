"""
FlashMind — AMM Pool Models
============================
Core simulation of every AMM type the agent interacts with.

Each pool class exposes:
    • get_amount_out(token_in_amount, token_in) → token_out_amount
    • get_amount_in(token_out_amount, token_out) → token_in_amount
    • spot_price(token_base, token_quote) → float
    • reserves → dict mapping token → float
    • fee_bps → int
    • swap(token_in, amount_in, token_out) → (amount_out, fee_paid)

These are **pure simulation models** — no on-chain calls. They model the
mathematical behaviour of each AMM given the current state.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .constants import (
    BALANCER_FEE_TIERS_BPS, CURVE_FEE_BPS,
    V2_FEE_BPS, V3_FEE_TIERS_BPS,
)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class Token:
    """Minimal token representation."""
    symbol: str
    decimals: int = 18

    def __hash__(self):
        return hash(self.symbol)

    def __eq__(self, other):
        return isinstance(other, Token) and self.symbol == other.symbol


@dataclass
class TickRange:
    """Uniswap V3 concentrated-liquidity tick range."""
    lower: int
    upper: int

    @property
    def width(self) -> int:
        return self.upper - self.lower


@dataclass
class LiquidityPosition:
    """A single LP position inside a V3-style pool."""
    owner: str
    liquidity: float          # in sqrt-price-space units
    tick_range: TickRange
    fee_growth_inside: Tuple[float, float] = (0.0, 0.0)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class AMMPool(ABC):
    """Base class every AMM pool model must implement."""

    def __init__(
        self,
        tokens: Tuple[Token, Token],
        fee_bps: int,
        protocol: str,
        address: str = "0x0",
    ):
        self.tokens = tokens
        self.token0, self.token1 = tokens
        self.fee_bps = fee_bps
        self.protocol = protocol
        self.address = address

    @abstractmethod
    def get_amount_out(self, amount_in: float, token_in: Token) -> float:
        ...

    @abstractmethod
    def get_amount_in(self, amount_out: float, token_out: Token) -> float:
        ...

    @abstractmethod
    def spot_price(self, token_base: Token, token_quote: Token) -> float:
        ...

    @property
    @abstractmethod
    def reserves(self) -> Dict[str, float]:
        ...

    def swap(
        self,
        token_in: Token,
        amount_in: float,
        token_out: Token,
    ) -> Tuple[float, float]:
        """
        Execute a swap through this pool.

        Returns (amount_out, fee_paid).
        """
        assert token_in in self.tokens and token_out in self.tokens
        assert token_in != token_out

        fee = amount_in * self.fee_bps / 10_000
        amount_after_fee = amount_in - fee
        amount_out = self.get_amount_out(amount_after_fee, token_in)
        return amount_out, fee

    def __repr__(self):
        return (
            f"{self.protocol}({self.token0.symbol}/{self.token1.symbol} "
            f"fee={self.fee_bps}bps @{self.address[:10]})"
        )


# ---------------------------------------------------------------------------
# Uniswap V2  (x * y = k)
# ---------------------------------------------------------------------------

class UniswapV2Pool(AMMPool):
    """
    Constant-product AMM:  x * y = k

    Used by: Uniswap V2, SushiSwap V2, PancakeSwap V2, SpiritSwap V2,
    and hundreds of Ethereum/L2 forks.
    """

    def __init__(
        self,
        token0: Token,
        token1: Token,
        reserve0: float,
        reserve1: float,
        fee_bps: int = V2_FEE_BPS,
        protocol: str = "uniswap_v2",
        address: str = "0x0",
    ):
        super().__init__((token0, token1), fee_bps, protocol, address)
        self._reserve0 = reserve0
        self._reserve1 = reserve1

    @property
    def reserve0(self) -> float:
        return self._reserve0

    @property
    def reserve1(self) -> float:
        return self._reserve1

    @property
    def k(self) -> float:
        return self._reserve0 * self._reserve1

    @property
    def reserves(self) -> Dict[str, float]:
        return {
            self.token0.symbol: self._reserve0,
            self.token1.symbol: self._reserve1,
        }

    def get_amount_out(self, amount_in: float, token_in: Token) -> float:
        if token_in == self.token0:
            reserve_in = self._reserve0
            reserve_out = self._reserve1
        else:
            reserve_in = self._reserve1
            reserve_out = self._reserve0

        # Constant product formula:  amount_out = (reserve_out * amount_in) / (reserve_in + amount_in)
        numerator = reserve_out * amount_in
        denominator = reserve_in + amount_in
        return numerator / denominator

    def get_amount_in(self, amount_out: float, token_out: Token) -> float:
        if token_out == self.token0:
            reserve_out = self._reserve0
            reserve_in = self._reserve1
        else:
            reserve_out = self._reserve1
            reserve_in = self._reserve0

        # Inverse:  amount_in = (reserve_in * amount_out) / (reserve_out - amount_out)
        numerator = reserve_in * amount_out
        denominator = reserve_out - amount_out
        if denominator <= 0:
            raise ValueError("Insufficient liquidity for this output")
        return numerator / denominator

    def spot_price(self, token_base: Token, token_quote: Token) -> float:
        """Price of 1 unit of token_base in terms of token_quote."""
        if token_base == self.token0:
            return self._reserve1 / self._reserve0
        return self._reserve0 / self._reserve1

    def set_reserves(self, reserve0: float, reserve1: float):
        """Update reserves (e.g. after an external swap or simulation step)."""
        self._reserve0 = reserve0
        self._reserve1 = reserve1


# ---------------------------------------------------------------------------
# Uniswap V3  (concentrated liquidity — simplified model)
# ---------------------------------------------------------------------------

class UniswapV3Pool(AMMPool):
    """
    Concentrated-liquidity AMM (Uniswap V3 and clones).

    We model the *active* liquidity within the current tick range as an
    effective constant-product pool with virtual reserves. This captures
    the essential price-impact behaviour without the full tick math.

    For research-grade accuracy you'd use the full Q64.96 sqrt-price
    representation, but for RL training this approximation is fast and
    captures the key non-linearities (steeper price impact in narrow ranges).
    """

    # Tick spacing constants
    TICK_SPACINGS = {100: 1, 500: 10, 3000: 60, 10000: 200}

    def __init__(
        self,
        token0: Token,
        token1: Token,
        liquidity: float,             # active liquidity (virtual)
        sqrt_price_x96: float,       # current sqrt(price) * 2^96
        fee_bps: int = 30,
        tick_range: Optional[TickRange] = None,
        protocol: str = "uniswap_v3",
        address: str = "0x0",
    ):
        super().__init__((token0, token1), fee_bps, protocol, address)
        self.liquidity = liquidity
        self.sqrt_price_x96 = sqrt_price_x96
        self.tick_range = tick_range or TickRange(-887272, 887272)

        # Derived virtual reserves
        self._compute_virtual_reserves()

    def _compute_virtual_reserves(self):
        """Derive virtual reserves from sqrt_price and liquidity."""
        # price = (sqrt_price_x96 / 2^96)^2
        self.price = (self.sqrt_price_x96 / (2 ** 96)) ** 2
        # Virtual reserves: L = sqrt(v0 * v1), price = v1/v0
        # => v0 = L / sqrt(price), v1 = L * sqrt(price)
        sqrt_p = math.sqrt(self.price)
        self.virtual_reserve0 = self.liquidity / sqrt_p
        self.virtual_reserve1 = self.liquidity * sqrt_p

    @property
    def reserves(self) -> Dict[str, float]:
        return {
            self.token0.symbol: self.virtual_reserve0,
            self.token1.symbol: self.virtual_reserve1,
        }

    def get_amount_out(self, amount_in: float, token_in: Token) -> float:
        if token_in == self.token0:
            reserve_in = self.virtual_reserve0
            reserve_out = self.virtual_reserve1
        else:
            reserve_in = self.virtual_reserve1
            reserve_out = self.virtual_reserve0

        numerator = reserve_out * amount_in
        denominator = reserve_in + amount_in
        return numerator / denominator

    def get_amount_in(self, amount_out: float, token_out: Token) -> float:
        if token_out == self.token0:
            reserve_out = self.virtual_reserve0
            reserve_in = self.virtual_reserve1
        else:
            reserve_out = self.virtual_reserve1
            reserve_in = self.virtual_reserve0

        numerator = reserve_in * amount_out
        denominator = reserve_out - amount_out
        if denominator <= 0:
            raise ValueError("Insufficient liquidity")
        return numerator / denominator

    def spot_price(self, token_base: Token, token_quote: Token) -> float:
        if token_base == self.token0:
            return self.price
        return 1.0 / self.price

    def update_price(self, new_sqrt_price_x96: float):
        """Move the price (e.g. after a large swap crosses a tick)."""
        self.sqrt_price_x96 = new_sqrt_price_x96
        self._compute_virtual_reserves()

    def effective_fee_multiplier(self) -> float:
        """
        V3 dynamic fee: base fee + fee_growth_inside last position.
        Simplified — just returns the base fee. Extend with real
        fee-growth tracking for production accuracy.
        """
        return self.fee_bps / 10_000


# ---------------------------------------------------------------------------
# Curve StableSwap  (stablecoin-optimized)
# ---------------------------------------------------------------------------

class CurvePool(AMMPool):
    """
    Curve StableSwap invariant (simplified 2-pool model).

    The invariant is:

        f(x) = D^3 / (4 * n^2 * x0 * x1) + ...  (amplified stable swap)

    We use the amplified constant-product approximation:

        x * y * A + (x + y) = D  (for small imbalances)

    In practice we implement the Newton-method solver used by Curve
    contracts. The amplification parameter A controls how "stable" the
    curve is (higher A = flatter around equilibrium = less price impact
    for stablecoin pairs).
    """

    def __init__(
        self,
        tokens: Tuple[Token, Token],
        reserves: Dict[str, float],
        amplification: int = 200,     # A parameter (typical: 50–2000)
        fee_bps: int = CURVE_FEE_BPS,
        protocol: str = "curve_v1",
        address: str = "0x0",
    ):
        super().__init__(tokens, fee_bps, protocol, address)
        self.amplification = amplification
        self._reserves = {t.symbol: r for t, r in zip(tokens, reserves.values())}
        self.A = amplification

    @property
    def reserves(self) -> Dict[str, float]:
        return dict(self._reserves)

    @property
    def D(self) -> float:
        """Total invariant D (virtual balance when pool is balanced)."""
        n = len(self.tokens)
        return sum(self._reserves.values())

    def _newton_D(self, reserves: List[float], A: int) -> float:
        """
        Newton's method to solve for D given reserves and amplification.
        This mirrors the actual Curve contract math.
        """
        n = len(reserves)
        Ann = A * n

        # Initial guess (sum of reserves)
        D = sum(reserves)

        for _ in range(255):  # Curve uses 255 iterations max
            D_prev = D
            S = sum(reserves)
            # Newton step
            numerator = D
            denominator = 0.0
            for x in reserves:
                numerator = numerator * D / (n * x)
                denominator += 1.0

            D = (Ann * S + numerator * denominator) * D / (
                (Ann - 1) * D + (n + 1) * numerator
            )
            if abs(D - D_prev) < 1e-6:
                break

        return D

    def _get_y(self, x: float, i: int, reserves: List[float]) -> float:
        """
        Solve for y given x and the invariant D.
        i = index of the token we are solving for.
        """
        D = self._newton_D(reserves, self.A)
        n = len(reserves)
        Ann = self.A * n

        c = D
        S = sum(reserves)

        for j in range(n):
            if j != i:
                c = c * D / (n * reserves[j])

        b = S + D / Ann - c
        # Newton iteration for y
        y = D
        for _ in range(255):
            y_prev = y
            numerator = y * y + b * y - c
            denominator = 2 * y + b
            y = numerator / denominator
            if abs(y - y_prev) < 1e-6:
                break

        return y

    def get_amount_out(self, amount_in: float, token_in: Token) -> float:
        reserves_list = [self._reserves[t.symbol] for t in self.tokens]
        i_in = [t.symbol for t in self.tokens].index(token_in.symbol)
        i_out = 1 - i_in

        # Apply fee
        fee = amount_in * self.fee_bps / 10_000
        dx = amount_in - fee

        # New balance of token_in after deposit
        new_reserve_in = reserves_list[i_in] + dx

        # Solve for new balance of token_out
        new_reserve_out = self._get_y(new_reserve_in, i_out, [
            new_reserve_in if j == i_in else reserves_list[j]
            for j in range(len(reserves_list))
        ])

        amount_out = reserves_list[i_out] - new_reserve_out
        return max(0.0, amount_out)

    def get_amount_in(self, amount_out: float, token_out: Token) -> float:
        # Numerical solve: binary search for amount_in
        lo, hi = 0.0, amount_out * 2.0
        for _ in range(128):
            mid = (lo + hi) / 2
            if self.get_amount_out(mid, self.token0 if token_out == self.token1 else self.token1) < amount_out:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    def spot_price(self, token_base: Token, token_quote: Token) -> float:
        r_base = self._reserves.get(token_base.symbol, 0)
        r_quote = self._reserves.get(token_quote.symbol, 0)
        if r_quote == 0:
            return float("inf")
        return r_base / r_quote


# ---------------------------------------------------------------------------
# Balancer V2  (weighted pool — generalized constant-product)
# ---------------------------------------------------------------------------

class BalancerV2Pool(AMMPool):
    """
    Weighted constant-product invariant (Balancer V2-style):

        prod(x_i^w_i) = k  (weighted constant-product invariant)

    Supports any number of tokens with arbitrary weights.
    """

    def __init__(
        self,
        tokens: Tuple[Token, ...],
        reserves: Dict[str, float],
        weights: Dict[str, float],
        fee_bps: int = 30,
        protocol: str = "balancer_v2",
        address: str = "0x0",
    ):
        super().__init__(tokens, fee_bps, protocol, address)
        self.tokens = tokens
        self._reserves = dict(reserves)
        self._weights = dict(weights)

        # Normalise weights to sum to 1
        total_w = sum(self._weights.values())
        for k in self._weights:
            self._weights[k] /= total_w

    @property
    def reserves(self) -> Dict[str, float]:
        return dict(self._reserves)

    @property
    def weights(self) -> Dict[str, float]:
        return dict(self._weights)

    def get_amount_out(self, amount_in: float, token_in: Token) -> float:
        w_in = self._weights[token_in.symbol]
        token_out = [t for t in self.tokens if t.symbol != token_in.symbol][0]
        w_out = self._weights[token_out.symbol]

        r_in = self._reserves[token_in.symbol]
        r_out = self._reserves[token_out.symbol]

        # Weighted formula:
        # amount_out = r_out * (1 - (r_in / (r_in + amount_in))^(w_in / w_out))
        ratio = r_in / (r_in + amount_in)
        exponent = w_in / w_out
        amount_out = r_out * (1.0 - ratio ** exponent)
        return amount_out

    def get_amount_in(self, amount_out: float, token_out: Token) -> float:
        w_out = self._weights[token_out.symbol]
        token_in = [t for t in self.tokens if t.symbol != token_out.symbol][0]
        w_in = self._weights[token_in.symbol]

        r_in = self._reserves[token_in.symbol]
        r_out = self._reserves[token_out.symbol]

        ratio = (r_out - amount_out) / r_out
        amount_in = r_in * (1.0 / ratio ** (w_out / w_in) - 1.0)
        return amount_in

    def spot_price(self, token_base: Token, token_quote: Token) -> float:
        w_base = self._weights[token_base.symbol]
        w_quote = self._weights[token_quote.symbol]
        r_base = self._reserves[token_base.symbol]
        r_quote = self._reserves[token_quote.symbol]
        return (r_base / w_base) / (r_quote / w_quote)


# ---------------------------------------------------------------------------
# Pool Factory
# ---------------------------------------------------------------------------

def create_pool(
    protocol: str,
    token0: Token,
    token1: Token,
    reserve0: float,
    reserve1: float,
    fee_bps: Optional[int] = None,
    **kwargs,
) -> AMMPool:
    """Factory function — create a pool by protocol name."""

    if protocol in (UNISWAP_V2 := "uniswap_v2", "sushiswap_v2", "pancake_v2"):
        return UniswapV2Pool(
            token0, token1, reserve0, reserve1,
            fee_bps=fee_bps or V2_FEE_BPS,
            protocol=protocol, **kwargs,
        )

    if protocol in ("uniswap_v3", "pancake_v3", "spirit_v3"):
        # Approximate V3 from reserves and a default fee tier
        sqrt_price = math.sqrt(reserve1 / reserve0) * (2 ** 96)
        liquidity = math.sqrt(reserve0 * reserve1)
        return UniswapV3Pool(
            token0, token1, liquidity, sqrt_price,
            fee_bps=fee_bps or 30,
            protocol=protocol, **kwargs,
        )

    if protocol == "curve_v1":
        return CurvePool(
            (token0, token1),
            {token0.symbol: reserve0, token1.symbol: reserve1},
            amplification=kwargs.get("amplification", 200),
            fee_bps=fee_bps or CURVE_FEE_BPS,
            protocol=protocol, **kwargs,
        )

    if protocol == "balancer_v2":
        weights = kwargs.get("weights", {token0.symbol: 0.5, token1.symbol: 0.5})
        return BalancerV2Pool(
            (token0, token1),
            {token0.symbol: reserve0, token1.symbol: reserve1},
            weights=weights,
            fee_bps=fee_bps or 30,
            protocol=protocol, **kwargs,
        )

    raise ValueError(f"Unknown protocol: {protocol}")


# ---------------------------------------------------------------------------
# Market — collection of pools for an episode
# ---------------------------------------------------------------------------

class Market:
    """
    Holds all pools the agent can observe and trade through.

    The Market is rebuilt at the start of every RL episode (or updated
    incrementally for continuous training).
    """

    def __init__(self):
        self.pools: Dict[str, AMMPool] = {}     # key = address
        self.token_registry: Dict[str, Token] = {}

    def add_pool(self, pool: AMMPool):
        self.pools[pool.address] = pool
        for t in pool.tokens:
            self.token_registry[t.symbol] = t

    def get_pool(self, address: str) -> Optional[AMMPool]:
        return self.pools.get(address)

    def get_pools_by_pair(
        self, token_a: str, token_b: str
    ) -> List[AMMPool]:
        """Return all pools that contain both tokens."""
        result = []
        for pool in self.pools.values():
            symbols = {t.symbol for t in pool.tokens}
            if token_a in symbols and token_b in symbols:
                result.append(pool)
        return result

    def get_all_pairs(self) -> List[Tuple[str, str]]:
        """Unique sorted token pairs across all pools."""
        pairs = set()
        for pool in self.pools.values():
            symbols = sorted(t.symbol for t in pool.tokens)
            for i in range(len(symbols)):
                for j in range(i + 1, len(symbols)):
                    pairs.add((symbols[i], symbols[j]))
        return sorted(pairs)

    def price_between(
        self,
        token_base: str,
        token_quote: str,
        via_pool: Optional[AMMPool] = None,
    ) -> float:
        """Get the best price for a pair across all pools."""
        pools = self.get_pools_by_pair(token_base, token_quote)
        if via_pool:
            pools = [via_pool]
        if not pools:
            return 0.0

        token_base_obj = self.token_registry.get(token_base)
        token_quote_obj = self.token_registry.get(token_quote)
        if not token_base_obj or not token_quote_obj:
            return 0.0

        best = 0.0
        for pool in pools:
            p = pool.spot_price(token_base_obj, token_quote_obj)
            if p > best:
                best = p
        return best

    def __len__(self):
        return len(self.pools)

    def __repr__(self):
        return f"Market({len(self.pools)} pools, {len(self.get_all_pairs())} pairs)"
