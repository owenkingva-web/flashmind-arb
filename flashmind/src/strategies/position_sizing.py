"""
FlashMind — Position Sizing
=============================
Advanced position-sizing strategies for DeFi arbitrage.

Provides:
    1. Kelly Criterion (full & fractional) for optimal bet sizing
    2. Volatility-adjusted sizing (inversely proportional to recent vol)
    3. Composite optimal size blending multiple signals

Usage:
    from src.strategies.position_sizing import PositionSizer, PositionConfig
    from src.strategies.engines import Opportunity

    config = PositionConfig(total_capital_eth=10.0)
    sizer = PositionSizer(total_capital=10.0, config=config)
    size = sizer.optimal_size(opportunity, market_state)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class PositionConfig:
    """Tuneable parameters for the position sizer."""

    max_position_pct: float = 0.2          # Max 20 % of capital per trade
    max_portfolio_risk: float = 0.05       # Max 5 % portfolio risk per trade
    min_position_eth: float = 0.01         # Minimum trade size in ETH
    kelly_fraction: float = 0.5            # Fractional-Kelly multiplier (0.5 = half-Kelly)
    volatility_window: int = 100           # Lookback window for volatility calc
    max_correlation_exposure: float = 0.3  # Max 30 % in correlated positions
    min_confidence: float = 0.3            # Minimum model confidence to size at all
    max_position_eth: Optional[float] = None  # Hard cap in ETH (None = no cap)
    base_gas_buffer: float = 1.5           # Gas cost buffer multiplier


# ===========================================================================
# Market state (lightweight, passed in at sizing time)
# ===========================================================================

@dataclass
class MarketState:
    """Snapshot of current market conditions used for sizing decisions."""

    recent_volatility: float = 0.0       # Std-dev of returns over lookback
    gas_price_gwei: float = 30.0        # Current gas price
    eth_price_usd: float = 2500.0       # ETH/USD price
    estimated_win_prob: float = 0.6     # Model-estimated win probability
    avg_win_eth: float = 0.01           # Average winning trade (ETH)
    avg_loss_eth: float = 0.005         # Average losing trade (ETH)
    portfolio_value_eth: float = 0.0    # Current portfolio value
    open_exposure_eth: float = 0.0      # Sum of open position values
    correlated_exposure_eth: float = 0.0  # Exposure in correlated positions
    num_recent_trades: int = 0          # Trades in rolling window
    recent_returns: List[float] = field(default_factory=list)


# ===========================================================================
# PositionSizer
# ===========================================================================

class PositionSizer:
    """
    Advanced position sizing for arbitrage opportunities.

    Combines:
        - Kelly Criterion (full & fractional)
        - Volatility-adjusted sizing
        - Portfolio-level risk limits
        - Confidence-gated minimums
    """

    def __init__(self, total_capital: float, config: Optional[PositionConfig] = None):
        self._total_capital = total_capital
        self._config = config or PositionConfig()

        # Running statistics for adaptive sizing
        self._trade_history: List[Dict[str, Any]] = []
        self._cumulative_pnl: float = 0.0
        self._max_cumulative_pnl: float = 0.0

    # ------------------------------------------------------------------
    # Kelly Criterion
    # ------------------------------------------------------------------

    def kelly_criterion(
        self,
        win_prob: float,
        win_amount: float,
        loss_amount: float,
    ) -> float:
        """
        Calculate the optimal Kelly fraction.

        Kelly formula:
            f* = (p * b - q) / b
        where
            p  = probability of winning
            q  = 1 - p
            b  = win_amount / loss_amount  (odds)

        Args:
            win_prob: Probability of a profitable trade (0–1).
            win_amount: Expected profit in ETH on a win.
            loss_amount: Expected loss in ETH on a loss.

        Returns:
            Optimal fraction of capital to risk (0.0 – 1.0).
            Returns 0.0 if the edge is negative.
        """
        if loss_amount <= 0 or win_prob <= 0 or win_prob >= 1:
            return 0.0

        q = 1.0 - win_prob
        b = win_amount / loss_amount  # odds

        kelly = (win_prob * b - q) / b

        if kelly <= 0.0:
            return 0.0

        # Clamp to [0, 1]
        return min(max(kelly, 0.0), 1.0)

    def kelly_fraction_adapted(
        self,
        win_prob: float,
        avg_win: float,
        avg_loss: float,
        max_fraction: float = 0.25,
    ) -> float:
        """
        Fractional Kelly for safer sizing.

        Applies the configured ``kelly_fraction`` multiplier (default: 0.5 = half-Kelly)
        and caps at *max_fraction*.

        Args:
            win_prob: Win probability (0–1).
            avg_win: Average profit in ETH on a win.
            avg_loss: Average loss in ETH on a loss.
            max_fraction: Hard upper bound on the fraction.

        Returns:
            Adjusted Kelly fraction.
        """
        full_kelly = self.kelly_criterion(win_prob, avg_win, avg_loss)
        adapted = full_kelly * self._config.kelly_fraction
        return min(adapted, max_fraction)

    # ------------------------------------------------------------------
    # Volatility-adjusted sizing
    # ------------------------------------------------------------------

    def volatility_adjusted_size(
        self,
        opportunity_pnl: float,
        recent_volatility: float,
        max_position_pct: float = 0.1,
    ) -> float:
        """
        Size inversely proportional to recent volatility.

        Higher volatility → smaller position to limit downside risk.

        Args:
            opportunity_pnl: Expected PnL of the opportunity in ETH.
            recent_volatility: Standard deviation of recent returns.
            max_position_pct: Maximum position as fraction of capital.

        Returns:
            Position fraction of total capital.
        """
        if recent_volatility <= 0:
            # No volatility signal — use a moderate default
            return max_position_pct * 0.5

        # Target: keep expected PnL ≈ volatility × scaling_factor
        # As vol increases, fraction decreases
        # Scale factor chosen so that at median vol (~0.02) we use ~50% of max
        target_risk_units = opportunity_pnl / max(recent_volatility, 1e-12)

        # Normalise: at low vol we approach max_position_pct
        vol_scale = 1.0 / (1.0 + recent_volatility * 50.0)
        fraction = max_position_pct * vol_scale

        # If the opportunity PnL is very large relative to vol, we can be more aggressive
        if target_risk_units > 2.0:
            fraction = min(fraction * 1.5, max_position_pct)

        return min(max(fraction, 0.0), max_position_pct)

    # ------------------------------------------------------------------
    # Composite optimal size
    # ------------------------------------------------------------------

    def optimal_size(
        self,
        opportunity: Any,
        market_state: MarketState,
    ) -> float:
        """
        Calculate optimal position size combining multiple methods.

        Blends:
            1. Kelly-based fraction (weighted by confidence)
            2. Volatility-adjusted fraction
            3. Portfolio-level constraints (max exposure, correlation)

        Returns absolute position size in ETH.
        """
        cfg = self._config
        confidence = getattr(opportunity, "confidence", 1.0)
        net_profit = getattr(opportunity, "net_profit", 0.0)
        risk_score = getattr(opportunity, "risk_score", 0.0)
        capital_required = getattr(opportunity, "capital_required", 0.0)

        # --- Gate: minimum confidence ---
        if confidence < cfg.min_confidence:
            logger.debug(
                "Skipping sizing: confidence %.3f < min %.3f",
                confidence, cfg.min_confidence,
            )
            return 0.0

        # --- 1. Kelly fraction ---
        kelly_frac = self.kelly_fraction_adapted(
            win_prob=market_state.estimated_win_prob,
            avg_win=market_state.avg_win_eth,
            avg_loss=market_state.avg_loss_eth,
            max_fraction=cfg.max_position_pct,
        )

        # --- 2. Volatility-adjusted fraction ---
        vol_frac = self.volatility_adjusted_size(
            opportunity_pnl=net_profit,
            recent_volatility=market_state.recent_volatility,
            max_position_pct=cfg.max_position_pct,
        )

        # --- 3. Blend: weighted average by confidence ---
        # Higher confidence → trust Kelly more; lower confidence → lean on vol sizing
        kelly_weight = confidence * 0.6
        vol_weight = 1.0 - kelly_weight
        blended = kelly_weight * kelly_frac + vol_weight * vol_frac

        # --- 4. Risk-score penalty ---
        # Higher risk_score → reduce size
        risk_penalty = 1.0 - (risk_score * 0.7)  # At risk=1.0 → 30% of blended
        blended *= max(risk_penalty, 0.05)

        # --- 5. Portfolio-level constraints ---
        blended = self._apply_portfolio_constraints(
            blended, market_state, cfg
        )

        # --- 6. Convert to absolute ETH ---
        position_eth = self.scale_to_capital(blended)

        # --- 7. Enforce minimums & maximums ---
        if position_eth < cfg.min_position_eth:
            logger.debug(
                "Position %.6f ETH below minimum %.6f — skipping",
                position_eth, cfg.min_position_eth,
            )
            return 0.0

        if cfg.max_position_eth is not None:
            position_eth = min(position_eth, cfg.max_position_eth)

        # Ensure we don't size larger than the opportunity's capital requirement
        # (for flash-loan arbs the required capital may differ)
        if capital_required > 0:
            position_eth = min(position_eth, capital_required)

        return round(position_eth, 8)

    # ------------------------------------------------------------------
    # Capital conversion
    # ------------------------------------------------------------------

    def scale_to_capital(self, fraction: float) -> float:
        """
        Convert a fraction (0.0–1.0) to an absolute capital amount in ETH.

        Args:
            fraction: Desired fraction of total capital.

        Returns:
            Absolute position size in ETH.
        """
        return fraction * self._total_capital

    # ------------------------------------------------------------------
    # Portfolio constraints
    # ------------------------------------------------------------------

    def _apply_portfolio_constraints(
        self,
        fraction: float,
        state: MarketState,
        cfg: PositionConfig,
    ) -> float:
        """
        Apply portfolio-level constraints that reduce the raw fraction.

        Constraints:
            - Maximum single-position cap
            - Portfolio risk budget (max_portfolio_risk)
            - Correlated exposure limit
            - Remaining capital after open positions
        """
        # 1. Max position cap
        fraction = min(fraction, cfg.max_position_pct)

        # 2. Portfolio risk budget
        if cfg.max_portfolio_risk > 0 and self._total_capital > 0:
            current_risk = state.open_exposure_eth / self._total_capital
            remaining_risk_budget = cfg.max_portfolio_risk - current_risk
            if remaining_risk_budget <= 0:
                return 0.0
            fraction = min(fraction, remaining_risk_budget)

        # 3. Correlated exposure limit
        if cfg.max_correlation_exposure > 0 and self._total_capital > 0:
            corr_ratio = state.correlated_exposure_eth / self._total_capital
            if corr_ratio >= cfg.max_correlation_exposure:
                return 0.0
            # Scale down proportionally as we approach the limit
            corr_headroom = 1.0 - (corr_ratio / cfg.max_correlation_exposure)
            fraction *= max(corr_headroom, 0.0)

        # 4. Remaining capital
        if self._total_capital > 0:
            used_capital = state.open_exposure_eth
            available = self._total_capital - used_capital
            if available <= 0:
                return 0.0
            fraction = min(fraction, available / self._total_capital)

        return fraction

    # ------------------------------------------------------------------
    # Trade recording (for adaptive updates)
    # ------------------------------------------------------------------

    def record_trade(
        self,
        size_eth: float,
        pnl_eth: float,
        strategy_name: str = "",
    ) -> None:
        """
        Record a completed trade for adaptive sizing.

        Updates internal statistics used by future sizing calls.
        """
        import time

        self._trade_history.append({
            "size_eth": size_eth,
            "pnl_eth": pnl_eth,
            "strategy": strategy_name,
            "timestamp": time.time(),
        })
        self._cumulative_pnl += pnl_eth
        self._max_cumulative_pnl = max(
            self._max_cumulative_pnl, self._cumulative_pnl
        )

        # Trim history to avoid unbounded growth
        if len(self._trade_history) > 5000:
            self._trade_history = self._trade_history[-2500:]

    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Return sizing-related performance statistics.

        Useful for diagnostics and the monitoring dashboard.
        """
        if not self._trade_history:
            return {
                "total_trades": 0,
                "win_rate": 0.0,
                "avg_win": 0.0,
                "avg_loss": 0.0,
                "current_drawdown_pct": 0.0,
                "total_pnl_eth": 0.0,
            }

        wins = [t for t in self._trade_history if t["pnl_eth"] > 0]
        losses = [t for t in self._trade_history if t["pnl_eth"] <= 0]

        total_pnl = self._cumulative_pnl
        drawdown = 0.0
        if self._max_cumulative_pnl > 0:
            drawdown = (self._max_cumulative_pnl - self._cumulative_pnl) / self._max_cumulative_pnl

        return {
            "total_trades": len(self._trade_history),
            "win_rate": len(wins) / len(self._trade_history),
            "avg_win": (sum(t["pnl_eth"] for t in wins) / len(wins)) if wins else 0.0,
            "avg_loss": (sum(t["pnl_eth"] for t in losses) / len(losses)) if losses else 0.0,
            "current_drawdown_pct": drawdown,
            "total_pnl_eth": total_pnl,
        }
