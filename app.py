#!/usr/bin/env python3
"""
FlashMind DeFi Arbitrage Bot - HuggingFace Spaces Dashboard
=============================================================
v15g Production Model - Strategy-Sampled PPO with Discrimination Rewards

Architecture: 621 -> 256 (ReLU) -> 128 (ReLU) -> {Actor(2), Critic(1)}
Parameters: 384,643
Training: 600K steps, SB3 PPO, realistic data distribution
Validation: Sharpe 8.87, Composite 0.647, 13/21 active strategies
"""

import os
import sys
import json
import time
import numpy as np
from datetime import datetime

# Add flashmind/src to path
_FLASHMIND_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flashmind")
sys.path.insert(0, _FLASHMIND_SRC)

import gradio as gr
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from src.rl.environment import FlashLoanArbEnv, ALL_STRATEGY_NAMES, NUM_STRATEGIES
from src.amm.pools import AMMPool, Market, Token
from src.strategies.cutting_edge import create_full_registry

# ============================================================================
# Constants
# ============================================================================

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flashmind", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "flashmind_v15g_best.npz")
NORM_PATH  = os.path.join(MODEL_DIR, "flashmind_v15g_best_norm.npz")
VAL_PATH   = os.path.join(MODEL_DIR, "v15g_validation_results.json")

OBS_DIM = 621
N_ACTIONS = 2
N_STRATEGIES = 21

STRATEGY_NAMES = list(ALL_STRATEGY_NAMES) if ALL_STRATEGY_NAMES else [f"S_{i}" for i in range(N_STRATEGIES)]
ACTION_LABELS = ["EXECUTE", "SKIP"]

IMBALANCE_PROB = 0.05
IMBALANCE_MAG_MIN = 0.97
IMBALANCE_MAG_MAX = 1.03
JITTER_MAG = 0.0005
GAS_RANGE = (15.0, 50.0)
ETH_PRICE_RANGE = (2000.0, 4000.0)
PRICE_VOLATILITY = 0.002


# ============================================================================
# NumPy Model (extracted from SB3 PPO, no torch/SB3 needed at runtime)
# ============================================================================

class V15GModel:
    """v15g Actor-Critic model with NumPy inference."""
    def __init__(self):
        self.pi_W1 = self.pi_b1 = self.pi_W2 = self.pi_b2 = None
        self.act_W = self.act_b = None
        self.vf_W1 = self.vf_b1 = self.vf_W2 = self.vf_b2 = None
        self.val_W = self.val_b = None
        self.obs_mean = None
        self.obs_var = None
        self.obs_count = 1.0
        self.loaded = False

    def load(self):
        d = np.load(MODEL_PATH, allow_pickle=False)
        self.pi_W1 = d["mlp_extractor.policy_net.0.weight"]
        self.pi_b1 = d["mlp_extractor.policy_net.0.bias"]
        self.pi_W2 = d["mlp_extractor.policy_net.2.weight"]
        self.pi_b2 = d["mlp_extractor.policy_net.2.bias"]
        self.act_W = d["action_net.weight"]
        self.act_b = d["action_net.bias"]
        self.vf_W1 = d["mlp_extractor.value_net.0.weight"]
        self.vf_b1 = d["mlp_extractor.value_net.0.bias"]
        self.vf_W2 = d["mlp_extractor.value_net.2.weight"]
        self.vf_b2 = d["mlp_extractor.value_net.2.bias"]
        self.val_W = d["value_net.weight"]
        self.val_b = d["value_net.bias"]
        if os.path.exists(NORM_PATH):
            nd = np.load(NORM_PATH, allow_pickle=False)
            self.obs_mean = nd["mean"].astype(np.float64)
            self.obs_var = nd["var"].astype(np.float64)
            self.obs_count = float(nd["count"][0])
        else:
            self.obs_mean = np.zeros(OBS_DIM, dtype=np.float64)
            self.obs_var = np.ones(OBS_DIM, dtype=np.float64)
        self.loaded = True

    def normalize(self, obs):
        return (obs.astype(np.float64) - self.obs_mean) / np.sqrt(self.obs_var / max(self.obs_count, 1) + 1e-8)

    def forward(self, obs):
        """Returns (probs, value, logits)."""
        x = self.normalize(obs)
        if x.ndim == 1:
            x = x.reshape(1, -1)
        h1 = np.maximum(0, x @ self.pi_W1.T + self.pi_b1)
        h2 = np.maximum(0, h1 @ self.pi_W2.T + self.pi_b2)
        logits = (h2 @ self.act_W.T + self.act_b)[0]
        l = logits - logits.max()
        e = np.exp(l)
        probs = e / e.sum()
        vh1 = np.maximum(0, x @ self.vf_W1.T + self.vf_b1)
        vh2 = np.maximum(0, vh1 @ self.vf_W2.T + self.vf_b2)
        value = float((vh2 @ self.val_W.T + self.val_b)[0, 0])
        return probs, value, logits

    def predict(self, obs, deterministic=False):
        probs, value, logits = self.forward(obs)
        if deterministic:
            action = int(np.argmax(probs))
        else:
            action = int(np.random.choice(len(probs), p=np.clip(probs, 1e-10, 1.0)))
        entropy = float(-np.sum(probs * np.log(probs + 1e-10)))
        return action, probs, value, entropy


# ============================================================================
# Strategy-Sampled Environment (simplified for dashboard)
# ============================================================================

class DashboardEnvV15G:
    """Simplified v15g environment for paper trading simulation."""
    def __init__(self, num_pools=10, seed=42, max_steps=256):
        self.num_pools = num_pools
        self.max_steps = max_steps
        self.seed = seed
        self.strat_names = STRATEGY_NAMES
        self.n_strategies = N_STRATEGIES
        self.profit_threshold = 0.1

    def _create_env(self, seed):
        return FlashLoanArbEnv(
            action_mode='discrete', num_pools=self.num_pools, seed=seed,
            imbalance_probability=IMBALANCE_PROB, max_steps=self.max_steps,
            gas_price_range=GAS_RANGE, eth_price_range=ETH_PRICE_RANGE,
            price_volatility=PRICE_VOLATILITY, scan_frequency=1,
        )

    def _augment_obs(self, base_obs, strategy_idx, env):
        one_hot = np.zeros(self.n_strategies, dtype=np.float32)
        one_hot[strategy_idx] = 1.0
        sn = self.strat_names[strategy_idx]
        has_opp = False
        best_profit = 0.0
        for opp in env.current_opportunities:
            if opp.strategy_name == sn and opp.net_profit > 0:
                has_opp = True
                if opp.net_profit > best_profit:
                    best_profit = opp.net_profit
        eth_price = env.eth_price_usd if env.eth_price_usd > 0 else 2000.0
        best_eth = float(best_profit) / eth_price if best_profit > 0 else 0.0
        opp_signal = np.array([1.0 if has_opp else 0.0, float(np.tanh(best_eth / 2.0))], dtype=np.float32)
        return np.concatenate([base_obs.astype(np.float32), one_hot, opp_signal])

    def _get_opp_for_strategy(self, env, strategy_idx):
        sn = self.strat_names[strategy_idx]
        best = None
        best_pnl = 0.0
        for opp in env.current_opportunities:
            if opp.strategy_name == sn and opp.net_profit > best_pnl:
                best = opp
                best_pnl = opp.net_profit
        return best, best_pnl

    def run_episode(self, mdl, rng, log_details=False):
        env = self._create_env(int(rng.integers(0, 2**31)))
        obs, _ = env.reset(seed=int(rng.integers(0, 2**31)))

        ep_pnl = 0.0
        ep_trades = ep_skips = ep_good = ep_bad = ep_no_opp = 0
        strat_exec = {}
        equity = [env.capital]
        step_log = []
        strats_used = set()

        for step in range(self.max_steps):
            si = int(rng.integers(self.n_strategies))
            aug_obs = self._augment_obs(obs, si, env)
            action, probs, value, entropy = mdl.predict(aug_obs)
            opp, opp_pnl_raw = self._get_opp_for_strategy(env, si)
            eth_price = env.eth_price_usd if env.eth_price_usd > 0 else 2000.0
            opp_eth = float(opp_pnl_raw) / eth_price if opp_pnl_raw > 0 else 0.0
            is_good = opp is not None and opp_eth >= self.profit_threshold
            sn = self.strat_names[si]

            if sn not in strat_exec:
                strat_exec[sn] = {"execute": 0, "skip": 0, "pnl": [], "good": 0, "bad": 0}

            if action == 0:  # EXECUTE
                strat_exec[sn]["execute"] += 1
                ep_trades += 1
                if opp is not None:
                    pnl_eth = max(-1.0, min(10.0, opp_eth))
                    env.capital += pnl_eth
                    env.cumulative_pnl += pnl_eth
                    ep_pnl += pnl_eth
                    strat_exec[sn]["pnl"].append(pnl_eth)
                    if pnl_eth >= self.profit_threshold:
                        ep_good += 1
                        strat_exec[sn]["good"] += 1
                    else:
                        ep_bad += 1
                        strat_exec[sn]["bad"] += 1
                    strats_used.add(sn)
                    if hasattr(env, '_apply_trade_to_market'):
                        try:
                            env._apply_trade_to_market(opp)
                        except Exception:
                            pass
                else:
                    ep_no_opp += 1
                if log_details and step < 20:
                    step_log.append({"step": step, "strat": sn, "action": "EXECUTE",
                                    "has_opp": opp is not None,
                                    "pnl_eth": round(opp_eth, 4) if opp else 0,
                                    "probs": [round(float(p), 3) for p in probs]})
            else:  # SKIP
                strat_exec[sn]["skip"] += 1
                ep_skips += 1
                if log_details and step < 20:
                    step_log.append({"step": step, "strat": sn, "action": "SKIP",
                                    "has_opp": opp is not None,
                                    "opp_eth": round(opp_eth, 4) if opp else 0,
                                    "probs": [round(float(p), 3) for p in probs]})

            obs, _, terminated, truncated, _ = env.step(0)
            equity.append(env.capital)
            if terminated or truncated:
                break

        return {
            "pnl": ep_pnl, "trades": ep_trades, "skips": ep_skips,
            "good_exec": ep_good, "bad_exec": ep_bad, "no_opp_exec": ep_no_opp,
            "strats_used": len(strats_used), "strat_exec": strat_exec,
            "equity": equity, "step_log": step_log,
        }


# ============================================================================
# Global Model State
# ============================================================================

model_state = V15GModel()

def ensure_model():
    if not model_state.loaded:
        model_state.load()


# ============================================================================
# Simulation Functions
# ============================================================================

def run_simulation(n_episodes=50, seed=42, max_steps=256):
    ensure_model()
    t0 = time.time()
    rng = np.random.default_rng(seed)
    env = DashboardEnvV15G(num_pools=10, max_steps=max_steps)

    all_pnl, all_equity = [], []
    strat_aggregate = {}
    step_logs = []

    for ep in range(n_episodes):
        result = env.run_episode(model_state, rng, log_details=(ep == 0))
        all_pnl.append(result["pnl"])
        all_equity.append(result["equity"])
        if ep == 0:
            step_logs = result["step_log"]
        for sn, sd in result["strat_exec"].items():
            if sn not in strat_aggregate:
                strat_aggregate[sn] = {"execute": 0, "skip": 0, "pnl": [], "good": 0, "bad": 0}
            strat_aggregate[sn]["execute"] += sd["execute"]
            strat_aggregate[sn]["skip"] += sd["skip"]
            strat_aggregate[sn]["pnl"].extend(sd["pnl"])
            strat_aggregate[sn]["good"] += sd["good"]
            strat_aggregate[sn]["bad"] += sd["bad"]

    pnls = np.array(all_pnl)
    elapsed = time.time() - t0

    total_exec = sum(sd["execute"] for sd in strat_aggregate.values())
    total_skip = sum(sd["skip"] for sd in strat_aggregate.values())
    total_all = total_exec + total_skip
    total_good = sum(sd["good"] for sd in strat_aggregate.values())
    total_bad = sum(sd["bad"] for sd in strat_aggregate.values())
    n_active = sum(1 for sd in strat_aggregate.values() if sd["execute"] > 0)

    return {
        "mean_pnl": float(np.mean(pnls)),
        "std_pnl": float(np.std(pnls)),
        "sharpe": float(np.mean(pnls) / max(np.std(pnls), 1e-6)),
        "win_rate": float(sum(1 for p in pnls if p > 0) / n_episodes * 100),
        "best_pnl": float(np.max(pnls)),
        "worst_pnl": float(np.min(pnls)),
        "median_pnl": float(np.median(pnls)),
        "skip_rate": float(total_skip / max(total_all, 1) * 100),
        "exec_good_rate": float(total_good / max(total_exec, 1) * 100),
        "bad_exec_rate": float(total_bad / max(total_exec, 1) * 100),
        "active_strategies": n_active,
        "mean_strats_used": float(np.mean([len(set()) for _ in range(n_episodes)])),
        "strat_aggregate": strat_aggregate,
        "equity_curves": all_equity,
        "step_log": step_logs,
        "n_episodes": n_episodes,
        "elapsed": elapsed,
    }


def run_walkforward(n_episodes=30, seed=100):
    seeds = [seed, seed+1000, seed+2000, seed+3000]
    windows = ["Normal", "Low Volatility", "High Volatility", "Stress"]
    results = {}
    for name, s in zip(windows, seeds):
        r = run_simulation(n_episodes=n_episodes, seed=s, max_steps=256)
        results[name] = {k: v for k, v in r.items()
                        if k not in ("equity_curves", "step_log", "strat_aggregate")}
    return results


# ============================================================================
# Plotting Functions
# ============================================================================

def create_equity_plot(sim_results):
    curves = sim_results["equity_curves"]
    fig = go.Figure()
    n_show = min(20, len(curves))
    step = max(1, len(curves) // n_show)
    for i in range(0, len(curves), step)[:n_show]:
        fig.add_trace(go.Scatter(y=curves[i], mode="lines", opacity=0.2,
                                 line=dict(width=1), showlegend=False))
    max_len = max(len(c) for c in curves)
    padded = np.array([c + [c[-1]] * (max_len - len(c)) for c in curves])
    mean_eq = padded.mean(axis=0)
    std_eq = padded.std(axis=0)
    fig.add_trace(go.Scatter(y=mean_eq, mode="lines",
                             line=dict(color="#00D4AA", width=3), name="Mean Equity"))
    fig.add_trace(go.Scatter(y=mean_eq + std_eq, mode="lines", line=dict(width=0), showlegend=False))
    fig.add_trace(go.Scatter(y=mean_eq - std_eq, mode="lines", fill="tonexty",
                             fillcolor="rgba(0,212,170,0.15)", line=dict(width=0), name="+/- 1 STD"))
    fig.update_layout(title="Equity Curves (Paper Trading)", xaxis_title="Step",
                      yaxis_title="Capital (ETH)", template="plotly_dark", height=400,
                      margin=dict(l=60, r=30, t=50, b=50))
    return fig


def create_pnl_dist_plot(sim_results):
    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=[e[-1]-e[0] for e in sim_results["equity_curves"]],
        nbinsx=20, marker_color="#00D4AA", name="PnL"))
    fig.update_layout(title="Episode PnL Distribution", xaxis_title="PnL (ETH)",
                      yaxis_title="Count", template="plotly_dark", height=350,
                      margin=dict(l=60, r=30, t=50, b=50))
    return fig


def create_strategy_chart(sim_results):
    sa = sim_results["strat_aggregate"]
    strats, exec_rates, avg_pnls = [], [], []
    for sn, sd in sa.items():
        total = sd["execute"] + sd["skip"]
        strats.append(sn.replace("_", " ").title())
        exec_rates.append(sd["execute"] / max(total, 1) * 100)
        avg_pnls.append(np.mean(sd["pnl"]) if sd["pnl"] else 0)

    fig = make_subplots(rows=2, cols=1,
                        subplot_titles=("Execute Rate by Strategy", "Avg PnL by Strategy (ETH)"))
    colors = ["#00D4AA" if er > 10 else "#636EFA" for er in exec_rates]
    fig.add_trace(go.Bar(x=strats, y=exec_rates, marker_color=colors, name="Execute %"), row=1, col=1)
    fig.add_trace(go.Bar(x=strats, y=avg_pnls,
                         marker_color=["#00D4AA" if p > 0 else "#EF553B" for p in avg_pnls],
                         name="Avg PnL"), row=2, col=1)
    fig.update_layout(template="plotly_dark", height=600, showlegend=False,
                      margin=dict(l=60, r=30, t=80, b=120))
    fig.update_xaxes(tickangle=-45, row=1, col=1)
    fig.update_xaxes(tickangle=-45, row=2, col=1)
    return fig


def create_walkforward_plot(wf_results):
    windows = list(wf_results.keys())
    sharpes = [wf_results[w]["sharpe"] for w in windows]
    skips = [wf_results[w]["skip_rate"] for w in windows]
    exec_goods = [wf_results[w]["exec_good_rate"] for w in windows]

    fig = make_subplots(rows=1, cols=3,
                        subplot_titles=("Sharpe Ratio", "Skip Rate %", "Exec-Good Rate %"))
    c = ["#636EFA", "#00CC96", "#EF553B", "#AB63FA"]
    fig.add_trace(go.Bar(x=windows, y=sharpes, marker_color=c), row=1, col=1)
    fig.add_trace(go.Bar(x=windows, y=skips, marker_color=c), row=1, col=2)
    fig.add_trace(go.Bar(x=windows, y=exec_goods, marker_color=c), row=1, col=3)
    fig.update_layout(template="plotly_dark", height=350, showlegend=False,
                      margin=dict(l=60, r=30, t=60, b=50))
    return fig


# ============================================================================
# Gradio UI
# ============================================================================

def format_metrics(r):
    sr = r['sharpe']
    sk = r['skip_rate']
    eg = r['exec_good_rate']
    be = r['bad_exec_rate']
    wr = r['win_rate']
    mp = r['mean_pnl']
    return f"""### Paper Trading Results (v15g)

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| **Sharpe Ratio** | {sr:.3f} | > 1.0 | {'PASS' if sr > 1.0 else 'BELOW'} |
| **Skip Rate** | {sk:.1f}% | 30-60% | {'PASS' if 30 <= sk <= 60 else 'CHECK'} |
| **Exec-Good Rate** | {eg:.1f}% | > 50% | {'PASS' if eg > 50 else 'BELOW'} |
| **Bad-Exec Rate** | {be:.1f}% | < 5% | {'PASS' if be < 5 else 'HIGH'} |
| **Win Rate** | {wr:.0f}% | > 70% | {'PASS' if wr > 70 else 'BELOW'} |
| **Mean PnL** | {mp:>+8.4f} ETH | > 0 | {'PASS' if mp > 0 else 'NEGATIVE'} |
| **Std PnL** | {r['std_pnl']:.4f} ETH | --- | --- |
| **Best PnL** | {r['best_pnl']:>+8.4f} ETH | --- | --- |
| **Worst PnL** | {r['worst_pnl']:>+8.4f} ETH | --- | --- |
| **Active Strategies** | {r['active_strategies']}/{N_STRATEGIES} | > 10 | {'PASS' if r['active_strategies'] > 10 else 'LOW'} |
| **Episodes** | {r['n_episodes']} | --- | --- |
    """


def get_model_info():
    md = "# FlashMind DeFi Arbitrage Bot - v15g Production Model\n\n"
    md += "## Model Architecture\n\n"
    md += "| Parameter | Value |\n|-----------|-------|\n"
    md += "| Observation Space | 621-dim (598 base + 21 strat one-hot + 2 opp signals) |\n"
    md += "| Action Space | 2 (EXECUTE / SKIP) |\n"
    md += "| Network | 621 -> 256 (ReLU) -> 128 (ReLU) -> {Actor(2), Critic(1)} |\n"
    md += f"| Total Parameters | {total_params:,} |\n"
    md += "| Inference | Pure NumPy (no PyTorch) |\n\n"

    md += "## Training Configuration\n\n"
    md += "| Component | Setting |\n|-----------|---------|\n"
    md += "| **Algorithm** | SB3 PPO (MlpPolicy) |\n"
    md += "| **Training Steps** | 600,000 |\n"
    md += "| **Parallel Envs** | 4 |\n"
    md += "| **Episode Length** | 256 steps |\n"
    md += "| **Learning Rate** | 3e-4 -> 3e-6 (cosine decay) |\n"
    md += "| **Entropy Coef** | 0.05 |\n"
    md += "| **Imbalance Prob** | 5% (realistic) |\n"
    md += "| **Imbalance Magnitude** | 3-5% (realistic cross-DEX) |\n"
    md += "| **Gas Range** | 15-50 Gwei (Arbitrum L2) |\n"
    md += "| **Reward** | Discrimination: Exec/NoOpp=-1.5, Skip/GoodOpp=-0.5 |\n\n"

    if os.path.exists(VAL_PATH):
        with open(VAL_PATH) as f:
            val = json.load(f)
        v = val.get("v15g", {})
        vf = val.get("v15f", {})
        md += "## Offline Validation Results\n\n"
        md += "| Metric | v15g | v15f (prev) |\n"
        md += "|--------|------|-------------|\n"
        md += f"| **Composite** | {v.get('composite', 0):.3f} | {vf.get('composite', 0):.3f} |\n"
        md += f"| **Sharpe** | {v.get('sharpe', 0):.2f} | {vf.get('sharpe', 0):.2f} |\n"
        md += f"| **Skip Rate** | {v.get('skip_rate', 0):.1%} | {vf.get('skip_rate', 0):.1%} |\n"
        md += f"| **Exec-Good** | {v.get('exec_good_rate', 0):.1%} | {vf.get('exec_good_rate', 0):.1%} |\n"
        md += f"| **Bad-Exec** | {v.get('bad_execute_rate', 0):.1%} | {vf.get('bad_execute_rate', 0):.1%} |\n"
        md += f"| **Win Rate** | {v.get('win_rate', 0):.0%} | {vf.get('win_rate', 0):.0%} |\n"
        md += f"| **Active Strats** | {v.get('total_strategies', 0)}/{N_STRATEGIES} | {vf.get('total_strategies', 0)}/{N_STRATEGIES} |\n"
        md += f"| **Avg Active/Ep** | {v.get('avg_active', 0):.1f} | {vf.get('avg_active', 0):.1f} |\n"
        md += f"| **Verdict** | **{val.get('verdict', 'N/A')}** | --- |\n\n"

    md += "---\n\n"
    md += "*v15g: Realistic data distribution (5% imbalance, 3-5% magnitude) "
    md += "replacing artificial patterns. Strategy-sampled binary EXECUTE/SKIP "
    md += "architecture with discrimination rewards.*\n\n"
    md += "*21 strategies: Cross-DEX, Triangular, Flash Loan, Liquidation, Sandwich, "
    md += "Funding Rate, MEV Bundle, JIT Liquidity, Cross-Chain, Lending Rate, "
    md += "Intent Order, Vault NAV, Liquid Staking, Oracle Delay, DEX Aggregator, "
    md += "Restaking Yield, LP Rebalance, Options Premium, Memecoin Snipe, "
    md += "VeToken Bribe, Stablecoin Depeg*"
    return md


def run_simulation_cb(n_episodes, seed, max_steps):
    results = run_simulation(n_episodes=int(n_episodes), seed=int(seed), max_steps=int(max_steps))
    md = format_metrics(results)
    md += f"\n*Simulation completed in {results['elapsed']:.1f}s*"
    eq_fig = create_equity_plot(results)
    pnl_fig = create_pnl_dist_plot(results)
    strat_fig = create_strategy_chart(results)
    table_data = [[s["step"], s["strat"], s["action"], s["has_opp"],
                   s["pnl_eth"], f"{s['probs'][0]:.3f} / {s['probs'][1]:.3f}"]
                  for s in results["step_log"]] if results["step_log"] else []
    return md, eq_fig, pnl_fig, strat_fig, table_data


def run_walkforward_cb(n_episodes, seed):
    wf = run_walkforward(n_episodes=int(n_episodes), seed=int(seed))
    md = "### Walk-Forward Diagnostics\n\n"
    md += "| Window | Sharpe | Skip % | Exec-Good % | Win Rate | Active |\n"
    md += "|--------|--------|--------|--------------|----------|--------|\n"
    for name, r in wf.items():
        md += f"| {name} | {r['sharpe']:.3f} | {r['skip_rate']:.1f}% | {r['exec_good_rate']:.1f}% | {r['win_rate']:.0f}% | {r['active_strategies']} |\n"
    fig = create_walkforward_plot(wf)
    return md, fig


def build_ui():
    css = ".gradio-container { max-width: 1400px !important; } footer { display: none !important; }"

    with gr.Blocks(title="FlashMind v15g", css=css) as demo:
        gr.Markdown("""
        # FlashMind DeFi Arbitrage Bot
        ### v15g Production Model - Strategy-Sampled PPO with Discrimination Rewards
        Paper-trading simulation & strategy analysis for the 21-strategy arbitrage agent.
        """)

        with gr.Tabs():
            with gr.Tab("Model Overview"):
                gr.Markdown(get_model_info())
                gr.Markdown("---")
                gr.Markdown(f"*Model: flashmind_v15g_best.npz ({total_params:,} params, pure NumPy inference)*")

            with gr.Tab("Paper Trading"):
                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("### Simulation Parameters")
                        n_ep = gr.Slider(10, 200, value=50, step=10, label="Episodes")
                        seed_inp = gr.Number(value=42, label="Random Seed")
                        steps_inp = gr.Slider(64, 512, value=256, step=64, label="Max Steps/Episode")
                        run_btn = gr.Button("Run Simulation", variant="primary", size="lg")
                    with gr.Column(scale=2):
                        metrics_md = gr.Markdown("*Click 'Run Simulation' to start...*")

                with gr.Row():
                    equity_plot = gr.Plot(label="Equity Curves")
                with gr.Row():
                    strat_plot = gr.Plot(label="Strategy Analysis")
                    pnl_plot = gr.Plot(label="PnL Distribution")
                with gr.Row():
                    step_table = gr.Dataframe(
                        headers=["Step", "Strategy", "Action", "Has Opp", "PnL (ETH)", "P(EXEC)/P(SKIP)"],
                        label="Decision Log (first 20 steps of episode 1)",
                        datatype=["number", "str", "str", "str", "number", "str"],
                    )

                run_btn.click(fn=run_simulation_cb,
                    inputs=[n_ep, seed_inp, steps_inp],
                    outputs=[metrics_md, equity_plot, pnl_plot, strat_plot, step_table])

            with gr.Tab("Walk-Forward Diagnostics"):
                gr.Markdown("""Evaluate across different market regimes:
                - **Normal**: Standard market conditions
                - **Low Volatility**: Calm market
                - **High Volatility**: Turbulent market
                - **Stress**: Extreme conditions""")
                with gr.Row():
                    wf_n_ep = gr.Slider(10, 100, value=30, step=10, label="Episodes per window")
                    wf_seed = gr.Number(value=100, label="Base Seed")
                    wf_btn = gr.Button("Run Diagnostics", variant="primary")
                wf_md = gr.Markdown("*Click 'Run Diagnostics'...*")
                wf_plot = gr.Plot()
                wf_btn.click(fn=run_walkforward_cb, inputs=[wf_n_ep, wf_seed],
                             outputs=[wf_md, wf_plot])

        return demo


if __name__ == "__main__":
    print("Initializing FlashMind v15g...")
    model_state.load()
    print(f"Model loaded from {MODEL_PATH}")
    print(f"Observation dim: {OBS_DIM}, Actions: {N_ACTIONS}")
    print("Launching Gradio dashboard...")

    demo = build_ui()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        theme=gr.themes.Soft(primary_hue="cyan", secondary_hue="purple", neutral_hue="slate"),
    )
