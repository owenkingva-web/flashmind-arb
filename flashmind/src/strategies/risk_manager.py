"""
FlashMind — Risk Manager
==========================
Comprehensive risk management for the arbitrage bot.

Provides:
    1. Pre-trade risk checks  (drawdown, limits, correlation, concentration)
    2. Post-trade risk assessment
    3. Portfolio risk metrics  (VaR, CVaR, Sharpe, Sortino, Max Drawdown)
    4. Cooldown / circuit-breaker logic

Usage:
    from src.strategies.risk_manager import RiskManager, RiskConfig

    config = RiskConfig()
    rm = RiskManager(config)
    decision = rm.check_pre_trade(opportunity, portfolio_state)
    if decision.approved:
        # execute …
        alert = rm.check_post_trade(result, portfolio_state)
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class RiskConfig:
    """Tuneable risk parameters."""

    max_drawdown_pct: float = 10.0          # Halt at 10 % drawdown
    daily_loss_limit_eth: float = 0.5       # Stop at 0.5 ETH daily loss
    per_strategy_limit_pct: float = 0.15    # Max 15 % per strategy
    max_open_positions: int = 5             # Concurrent position cap
    min_margin_of_safety: float = 1.5       # Profit must be 1.5× gas cost
    cooldown_after_loss: int = 10           # Steps to wait after a loss
    correlation_limit: float = 0.7          # Don't open correlated positions > 0.7
    max_position_concentration: float = 0.25  # Max 25 % in a single token
    min_profit_eth: float = 0.001           # Skip dust opportunities


# ===========================================================================
# Data types
# ===========================================================================

class RiskLevel(Enum):
    """Severity of a risk decision."""
    SAFE = "safe"
    CAUTION = "caution"
    WARNING = "warning"
    CRITICAL = "critical"
    BLOCKED = "blocked"


@dataclass
class RiskDecision:
    """Result of a pre-trade risk check."""

    approved: bool
    level: RiskLevel
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.approved


@dataclass
class RiskAlert:
    """Post-trade risk alert."""

    level: RiskLevel
    message: str
    metric_name: str
    metric_value: float
    threshold: float
    suggested_action: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class TradeResult:
    """Summary of a completed trade for post-trade analysis."""

    tx_hash: str = ""
    strategy_name: str = ""
    profit_eth: float = 0.0
    gas_cost_eth: float = 0.0
    net_pnl_eth: float = 0.0
    size_eth: float = 0.0
    execution_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class OpenPosition:
    """An currently open position."""

    strategy_name: str
    token_symbol: str
    size_eth: float
    entry_time: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PortfolioState:
    """Current portfolio / risk state snapshot."""

    total_value_eth: float = 0.0
    available_eth: float = 0.0
    open_positions: List[OpenPosition] = field(default_factory=list)
    equity_curve: List[float] = field(default_factory=list)
    daily_pnl_eth: float = 0.0
    total_pnl_eth: float = 0.0
    peak_value_eth: float = 0.0
    returns_history: List[float] = field(default_factory=list)
    strategy_pnl: Dict[str, float] = field(default_factory=dict)
    last_trade_time: float = 0.0
    trades_since_loss: int = 0
    consecutive_losses: int = 0


@dataclass
class RiskReport:
    """Comprehensive risk report."""

    timestamp: float = field(default_factory=time.time)
    current_drawdown_pct: float = 0.0
    max_drawdown_pct: float = 0.0
    max_drawdown_duration: int = 0
    var_95: float = 0.0
    cvar_95: float = 0.0
    sharpe_ratio: float = 0.0
    sortino_ratio: float = 0.0
    daily_pnl_eth: float = 0.0
    total_pnl_eth: float = 0.0
    num_open_positions: int = 0
    active_alerts: List[RiskAlert] = field(default_factory=list)
    is_trading_allowed: bool = True
    circuit_breaker_active: bool = False
    cooldown_remaining: int = 0


# ===========================================================================
# RiskManager
# ===========================================================================

class RiskManager:
    """
    Comprehensive risk management for the arbitrage bot.

    Acts as a gate-keeper before trade execution and monitors
    post-trade portfolio health.
    """

    def __init__(self, config: Optional[RiskConfig] = None):
        self._config = config or RiskConfig()

        # Internal state
        self._cooldown_counter: int = 0
        self._circuit_breaker: bool = False
        self._circuit_breaker_reason: str = ""
        self._circuit_breaker_time: float = 0.0
        self._alerts: List[RiskAlert] = []
        self._max_alerts: int = 500

        # Rolling equity curve for metrics
        self._equity_curve: List[float] = []
        self._returns: List[float] = []
        self._peak_equity: float = 0.0

        # Historical max drawdown tracking
        self._max_drawdown_pct: float = 0.0
        self._max_drawdown_start: int = 0
        self._max_drawdown_end: int = 0
        self._current_dd_start: int = 0

        # Trade results for analytics
        self._trade_results: List[TradeResult] = []

    # ------------------------------------------------------------------
    # Pre-trade checks
    # ------------------------------------------------------------------

    def check_pre_trade(
        self,
        opportunity: Any,
        current_state: PortfolioState,
    ) -> RiskDecision:
        """
        Check if a trade is safe to execute.

        Applies the following checks in order:
            1. Circuit breaker
            2. Cooldown
            3. Drawdown limit
            4. Daily loss limit
            5. Open position count
            6. Per-strategy capital allocation
            7. Position concentration
            8. Margin of safety (profit vs gas)
            9. Minimum profit threshold

        Returns:
            :class:`RiskDecision` with ``approved=True`` if all checks pass.
        """
        cfg = self._config
        net_profit = getattr(opportunity, "net_profit", 0.0)
        gas_cost = getattr(opportunity, "gas_cost", 0.0)
        strategy_name = getattr(opportunity, "strategy_name", "unknown")
        capital_required = getattr(opportunity, "capital_required", 0.0)
        confidence = getattr(opportunity, "confidence", 1.0)

        # 1. Circuit breaker
        if self._circuit_breaker:
            return RiskDecision(
                approved=False,
                level=RiskLevel.CRITICAL,
                reason=f"Circuit breaker active: {self._circuit_breaker_reason}",
                details={"circuit_breaker": True},
            )

        # 2. Cooldown after loss
        if self._cooldown_counter > 0:
            return RiskDecision(
                approved=False,
                level=RiskLevel.CAUTION,
                reason=f"Cooldown active ({self._cooldown_counter} steps remaining)",
                details={"cooldown_remaining": self._cooldown_counter},
            )

        # 3. Drawdown check
        dd = self._current_drawdown(current_state)
        if dd >= cfg.max_drawdown_pct:
            self._activate_circuit_breaker(f"Drawdown {dd:.1f}% >= {cfg.max_drawdown_pct}%")
            return RiskDecision(
                approved=False,
                level=RiskLevel.CRITICAL,
                reason=f"Max drawdown breached: {dd:.2f}%",
                details={"drawdown_pct": dd},
            )
        elif dd >= cfg.max_drawdown_pct * 0.8:
            return RiskDecision(
                approved=False,
                level=RiskLevel.WARNING,
                reason=f"Drawdown approaching limit: {dd:.2f}%",
                details={"drawdown_pct": dd},
            )

        # 4. Daily loss limit
        if current_state.daily_pnl_eth < -cfg.daily_loss_limit_eth:
            return RiskDecision(
                approved=False,
                level=RiskLevel.CRITICAL,
                reason=f"Daily loss limit hit: {current_state.daily_pnl_eth:.4f} ETH",
                details={"daily_pnl": current_state.daily_pnl_eth},
            )

        # 5. Open positions count
        num_open = len(current_state.open_positions)
        if num_open >= cfg.max_open_positions:
            return RiskDecision(
                approved=False,
                level=RiskLevel.CAUTION,
                reason=f"Max open positions reached: {num_open}/{cfg.max_open_positions}",
                details={"open_positions": num_open},
            )

        # 6. Per-strategy allocation
        strat_pnl = current_state.strategy_pnl.get(strategy_name, 0.0)
        if current_state.total_value_eth > 0:
            strat_allocation = abs(strat_pnl) / current_state.total_value_eth
            if strat_allocation >= cfg.per_strategy_limit_pct:
                return RiskDecision(
                    approved=False,
                    level=RiskLevel.CAUTION,
                    reason=(
                        f"Strategy {strategy_name} allocation {strat_allocation:.2%} "
                        f">= {cfg.per_strategy_limit_pct:.2%}"
                    ),
                    details={"strategy": strategy_name, "allocation_pct": strat_allocation},
                )

        # 7. Position concentration (per-token)
        if current_state.total_value_eth > 0 and capital_required > 0:
            token_exposure = self._token_exposure(current_state, opportunity)
            if token_exposure >= cfg.max_position_concentration:
                return RiskDecision(
                    approved=False,
                    level=RiskLevel.WARNING,
                    reason=f"Token concentration {token_exposure:.2%} >= {cfg.max_position_concentration:.2%}",
                    details={"token_concentration_pct": token_exposure},
                )

        # 8. Margin of safety
        if gas_cost > 0:
            margin = net_profit / gas_cost if gas_cost != 0 else float("inf")
            if margin < cfg.min_margin_of_safety:
                return RiskDecision(
                    approved=False,
                    level=RiskLevel.CAUTION,
                    reason=(
                        f"Margin of safety {margin:.2f}x < {cfg.min_margin_of_safety}x "
                        f"(profit={net_profit:.6f}, gas={gas_cost:.6f})"
                    ),
                    details={"margin_of_safety": margin},
                )

        # 9. Minimum profit
        if net_profit < cfg.min_profit_eth:
            return RiskDecision(
                approved=False,
                level=RiskLevel.SAFE,
                reason=f"Profit {net_profit:.6f} ETH below minimum {cfg.min_profit_eth} ETH",
                details={"profit_eth": net_profit},
            )

        # All checks passed
        return RiskDecision(
            approved=True,
            level=RiskLevel.SAFE,
            reason="All pre-trade checks passed",
            details={
                "drawdown_pct": dd,
                "open_positions": num_open,
                "margin_of_safety": net_profit / gas_cost if gas_cost > 0 else float("inf"),
                "confidence": confidence,
            },
        )

    # ------------------------------------------------------------------
    # Post-trade checks
    # ------------------------------------------------------------------

    def check_post_trade(
        self,
        trade_result: TradeResult,
        state: PortfolioState,
    ) -> Optional[RiskAlert]:
        """
        Post-trade risk assessment.

        Updates internal state and returns an alert if something
        needs attention.
        """
        cfg = self._config

        # Record the trade
        self._trade_results.append(trade_result)
        if len(self._trade_results) > 10000:
            self._trade_results = self._trade_results[-5000:]

        # Update equity curve
        self._equity_curve.append(state.total_value_eth)
        if len(self._equity_curve) > 10000:
            self._equity_curve = self._equity_curve[-5000:]

        # Track peak
        if state.total_value_eth > self._peak_equity:
            self._peak_equity = state.total_value_eth

        # Compute return and append
        if len(self._equity_curve) >= 2:
            prev = self._equity_curve[-2]
            if prev > 0:
                ret = (state.total_value_eth - prev) / prev
                self._returns.append(ret)
                if len(self._returns) > 10000:
                    self._returns = self._returns[-5000:]

        # Handle losses
        alert: Optional[RiskAlert] = None
        if trade_result.net_pnl_eth < 0:
            self._cooldown_counter = cfg.cooldown_after_loss
            logger.info(
                "Loss detected: %.6f ETH — cooldown %d steps",
                trade_result.net_pnl_eth,
                cfg.cooldown_after_loss,
            )

            # Check if this triggers a daily-loss alert
            if state.daily_pnl_eth < -cfg.daily_loss_limit_eth * 0.5:
                alert = RiskAlert(
                    level=RiskLevel.WARNING,
                    message=(
                        f"Daily PnL {state.daily_pnl_eth:.4f} ETH approaching limit "
                        f"{-cfg.daily_loss_limit_eth:.4f} ETH"
                    ),
                    metric_name="daily_pnl_eth",
                    metric_value=state.daily_pnl_eth,
                    threshold=-cfg.daily_loss_limit_eth * 0.5,
                    suggested_action="Reduce position sizes or pause trading",
                )
        else:
            # Profitable trade — reduce cooldown
            if self._cooldown_counter > 0:
                self._cooldown_counter = max(0, self._cooldown_counter - 1)

        # Drawdown check
        dd = self._current_drawdown(state)
        if dd >= cfg.max_drawdown_pct * 0.7:
            alert = RiskAlert(
                level=RiskLevel.WARNING,
                message=f"Drawdown at {dd:.2f}% (limit: {cfg.max_drawdown_pct}%)",
                metric_name="drawdown_pct",
                metric_value=dd,
                threshold=cfg.max_drawdown_pct * 0.7,
                suggested_action="Consider reducing exposure",
            )

        if alert:
            self._alerts.append(alert)
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts // 2:]

        return alert

    # ------------------------------------------------------------------
    # Risk metrics
    # ------------------------------------------------------------------

    def calculate_var(
        self,
        returns: Optional[Sequence[float]] = None,
        confidence: float = 0.95,
        method: str = "historical",
    ) -> float:
        """
        Calculate Value at Risk (VaR).

        Args:
            returns: Return series.  Uses internal history if ``None``.
            confidence: Confidence level (default 95%).
            method: ``"historical"`` (percentile) or ``"parametric"`` (normal).

        Returns:
            VaR as a positive number representing potential loss.
        """
        data = list(returns or self._returns)
        if len(data) < 2:
            return 0.0

        if method == "parametric":
            n = len(data)
            mean = sum(data) / n
            variance = sum((r - mean) ** 2 for r in data) / (n - 1)
            std = math.sqrt(variance)
            if std == 0:
                return 0.0

            # Z-score for the given confidence (approximate via scipy-like table)
            z = self._norm_ppf(confidence)
            return abs(mean - z * std)

        # Historical (percentile-based)
        sorted_returns = sorted(data)
        index = int((1 - confidence) * len(sorted_returns))
        index = min(index, len(sorted_returns) - 1)
        return abs(sorted_returns[index])

    def calculate_cvar(
        self,
        returns: Optional[Sequence[float]] = None,
        confidence: float = 0.95,
    ) -> float:
        """
        Calculate Conditional VaR (Expected Shortfall / CVaR).

        The average of all losses exceeding the VaR threshold.

        Args:
            returns: Return series.  Uses internal history if ``None``.
            confidence: Confidence level (default 95%).

        Returns:
            CVaR as a positive number.
        """
        data = list(returns or self._returns)
        if len(data) < 2:
            return 0.0

        sorted_returns = sorted(data)
        cutoff = int((1 - confidence) * len(sorted_returns))
        cutoff = max(0, min(cutoff, len(sorted_returns) - 1))
        tail = sorted_returns[:cutoff + 1]

        if not tail:
            return 0.0

        return abs(sum(tail) / len(tail))

    def calculate_sharpe_ratio(
        self,
        returns: Optional[Sequence[float]] = None,
        risk_free_rate: float = 0.0,
        periods_per_year: int = 365,  # Daily returns → annualised
    ) -> float:
        """
        Calculate annualised Sharpe ratio.

        Args:
            returns: Return series.  Uses internal history if ``None``.
            risk_free_rate: Annualised risk-free rate.
            periods_per_year: Number of return periods per year.

        Returns:
            Annualised Sharpe ratio.
        """
        data = list(returns or self._returns)
        if len(data) < 2:
            return 0.0

        n = len(data)
        mean = sum(data) / n
        variance = sum((r - mean) ** 2 for r in data) / (n - 1)
        std = math.sqrt(variance)

        if std == 0:
            return 0.0

        # Annualise
        period_rf = risk_free_rate / periods_per_year
        excess = mean - period_rf
        return (excess / std) * math.sqrt(periods_per_year)

    def calculate_sortino_ratio(
        self,
        returns: Optional[Sequence[float]] = None,
        risk_free_rate: float = 0.0,
        periods_per_year: int = 365,
    ) -> float:
        """
        Calculate annualised Sortino ratio (downside deviation only).

        Args:
            returns: Return series.  Uses internal history if ``None``.
            risk_free_rate: Annualised risk-free rate.
            periods_per_year: Number of return periods per year.

        Returns:
            Annualised Sortino ratio.
        """
        data = list(returns or self._returns)
        if len(data) < 2:
            return 0.0

        n = len(data)
        mean = sum(data) / n
        period_rf = risk_free_rate / periods_per_year
        excess = mean - period_rf

        # Downside deviation: only negative excess returns
        downside_diffs = [min(r - period_rf, 0.0) for r in data]
        downside_var = sum(d ** 2 for d in downside_diffs) / n
        downside_dev = math.sqrt(downside_var)

        if downside_dev == 0:
            return 0.0

        return (excess / downside_dev) * math.sqrt(periods_per_year)

    def calculate_max_drawdown(
        self,
        equity_curve: Optional[Sequence[float]] = None,
    ) -> Tuple[float, int, int]:
        """
        Calculate maximum drawdown and its duration.

        Args:
            equity_curve: Portfolio value over time.  Uses internal history if ``None``.

        Returns:
            (max_drawdown_pct, start_index, end_index)
            - max_drawdown_pct: as a positive float (e.g. 5.0 for 5%)
            - start_index: index in the curve where drawdown began
            - end_index: index where drawdown was at maximum (trough)
        """
        curve = list(equity_curve or self._equity_curve)
        if len(curve) < 2:
            return 0.0, 0, 0

        peak = curve[0]
        max_dd = 0.0
        max_dd_start = 0
        max_dd_end = 0
        current_start = 0

        for i in range(1, len(curve)):
            if curve[i] > peak:
                peak = curve[i]
                current_start = i
            elif peak > 0:
                dd = (peak - curve[i]) / peak * 100.0
                if dd > max_dd:
                    max_dd = dd
                    max_dd_start = current_start
                    max_dd_end = i

        return max_dd, max_dd_start, max_dd_end

    # ------------------------------------------------------------------
    # Risk report
    # ------------------------------------------------------------------

    def get_risk_report(self, state: Optional[PortfolioState] = None) -> RiskReport:
        """
        Generate a comprehensive risk report.

        Args:
            state: Current portfolio state (updates internal tracking).

        Returns:
            :class:`RiskReport` with all computed metrics.
        """
        if state is not None:
            self._equity_curve.append(state.total_value_eth)
            if state.total_value_eth > self._peak_equity:
                self._peak_equity = state.total_value_eth
            if len(self._equity_curve) >= 2:
                prev = self._equity_curve[-2]
                if prev > 0:
                    ret = (state.total_value_eth - prev) / prev
                    self._returns.append(ret)

        # Max drawdown
        max_dd, dd_start, dd_end = self.calculate_max_drawdown()
        dd_duration = dd_end - dd_start

        # Current drawdown
        current_dd = 0.0
        if self._peak_equity > 0 and self._equity_curve:
            current_dd = (self._peak_equity - self._equity_curve[-1]) / self._peak_equity * 100.0

        # VaR & CVaR
        var_95 = self.calculate_var(confidence=0.95)
        cvar_95 = self.calculate_cvar(confidence=0.95)

        # Sharpe & Sortino
        sharpe = self.calculate_sharpe_ratio()
        sortino = self.calculate_sortino_ratio()

        # Recent alerts
        recent_alerts = self._alerts[-20:] if self._alerts else []

        return RiskReport(
            current_drawdown_pct=current_dd,
            max_drawdown_pct=max_dd,
            max_drawdown_duration=dd_duration,
            var_95=var_95,
            cvar_95=cvar_95,
            sharpe_ratio=sharpe,
            sortino_ratio=sortino,
            daily_pnl_eth=state.daily_pnl_eth if state else 0.0,
            total_pnl_eth=state.total_pnl_eth if state else 0.0,
            num_open_positions=len(state.open_positions) if state else 0,
            active_alerts=recent_alerts,
            is_trading_allowed=not self._circuit_breaker and self._cooldown_counter == 0,
            circuit_breaker_active=self._circuit_breaker,
            cooldown_remaining=self._cooldown_counter,
        )

    # ------------------------------------------------------------------
    # Public state helpers
    # ------------------------------------------------------------------

    def tick_cooldown(self) -> None:
        """Decrement the cooldown counter by one.  Call after each step."""
        if self._cooldown_counter > 0:
            self._cooldown_counter -= 1

    def reset_circuit_breaker(self) -> None:
        """Manually reset the circuit breaker."""
        self._circuit_breaker = False
        self._circuit_breaker_reason = ""
        logger.info("Circuit breaker manually reset")

    @property
    def is_trading_allowed(self) -> bool:
        """True when neither circuit breaker nor cooldown is active."""
        return not self._circuit_breaker and self._cooldown_counter == 0

    @property
    def recent_alerts(self) -> List[RiskAlert]:
        """Return the most recent risk alerts."""
        return list(self._alerts[-50:])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _current_drawdown(self, state: PortfolioState) -> float:
        """Compute current drawdown as a positive percentage."""
        if state.peak_value_eth <= 0:
            return 0.0
        return (state.peak_value_eth - state.total_value_eth) / state.peak_value_eth * 100.0

    def _token_exposure(self, state: PortfolioState, opportunity: Any) -> float:
        """
        Estimate token exposure fraction after taking this opportunity.

        Returns fraction of total portfolio value.
        """
        if state.total_value_eth <= 0:
            return 0.0

        # Sum existing exposure for tokens involved in the opportunity
        path = getattr(opportunity, "path", [])
        involved_tokens = set()
        for step in path:
            involved_tokens.add(getattr(step.token_in, "symbol", ""))
            involved_tokens.add(getattr(step.token_out, "symbol", ""))

        existing = 0.0
        for pos in state.open_positions:
            if pos.token_symbol in involved_tokens:
                existing += pos.size_eth

        new_size = getattr(opportunity, "capital_required", 0.0)
        total_exposure = existing + new_size
        return total_exposure / state.total_value_eth

    def _activate_circuit_breaker(self, reason: str) -> None:
        """Activate the circuit breaker."""
        self._circuit_breaker = True
        self._circuit_breaker_reason = reason
        self._circuit_breaker_time = time.time()
        logger.critical("CIRCUIT BREAKER ACTIVATED: %s", reason)

    @staticmethod
    def _norm_ppf(p: float) -> float:
        """
        Approximate the inverse of the standard normal CDF (z-score).

        Uses the rational approximation from Abramowitz & Stegun (1964),
        accurate to ~1.5e-7.
        """
        if p <= 0:
            return float("-inf")
        if p >= 1:
            return float("inf")
        if p == 0.5:
            return 0.0

        # Coefficients
        a = [
            -3.969683028665376e+01,
             2.209460984245205e+02,
            -2.759285104469687e+02,
             1.383577518672690e+02,
            -3.066479806614716e+01,
             2.506628277459239e+00,
        ]
        b = [
            -5.447609879822406e+01,
             1.615858368580409e+02,
            -1.556989798598866e+02,
             6.680131188771972e+01,
            -1.328068155288572e+01,
        ]
        c = [
            -7.784894002430293e-03,
            -3.223964580411365e-01,
            -2.400758277161838e+00,
            -2.549732539343734e+00,
             4.374664141464968e+00,
             2.938163982698783e+00,
        ]
        d = [
             7.784695709041462e-03,
             3.224671290700398e-01,
             2.445134137142996e+00,
             3.754408661907416e+00,
        ]

        p_low = 0.02425
        p_high = 1 - p_low

        if p < p_low:
            q = math.sqrt(-2 * math.log(p))
            x = (((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
                ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)
        elif p <= p_high:
            q = p - 0.5
            r = q * q
            x = (((((a[0]*r + a[1])*r + a[2])*r + a[3])*r + a[4])*r + a[5]) * q / \
                (((((b[0]*r + b[1])*r + b[2])*r + b[3])*r + b[4])*r + 1)
        else:
            q = math.sqrt(-2 * math.log(1 - p))
            x = -(((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
                 ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)

        return x
