---
title: FlashMind DeFi Arbitrage Bot
emoji: ✈
colorFrom: cyan
colorTo: purple
sdk: gradio
sdk_version: "5.0.0"
pinned: false
---

# FlashMind DeFi Arbitrage Bot - v15g

Interactive paper-trading simulation & strategy analysis dashboard for the **v15g** PPO-trained MEV strategy engine.

## What's New in v15g

- **Strategy-Sampled Architecture**: 621-dim observations (598 base + 21 strategy one-hot + 2 opportunity signals)
- **Binary Actions**: EXECUTE / SKIP decision per strategy
- **Realistic Data Distribution**: 5% imbalance probability, 3-5% magnitude
- **Discrimination Rewards**: Penalizes false executions and missed opportunities
- **600K Training Steps**: SB3 PPO with cosine LR decay
- **13/21 Active Strategies**: Sharpe 8.87, Composite 0.647

## Validation Results

| Metric | v15g |
|--------|------|
| Composite Score | 0.647 |
| Sharpe Ratio | 8.87 |
| Skip Rate | 43.8% |
| Exec-Good Rate | 53.7% |
| Bad-Exec Rate | 2.6% |
| Win Rate | 100% |
| Active Strategies | 13/21 |

## Architecture

| Parameter | Value |
|-----------|-------|
| Observation Space | 621-dim |
| Action Space | 2 (EXECUTE/SKIP) |
| Network | 621 -> 256 (ReLU) -> 128 (ReLU) -> Actor(2), Critic(1) |
| Parameters | 384,643 |
| Inference | Pure NumPy (no PyTorch) |
