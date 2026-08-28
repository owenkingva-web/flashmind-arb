"""
FlashMind — Default Configuration
=====================================
Central configuration file for the entire system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MarketConfig:
    num_pools: int = 30
    num_extra_tokens: int = 5
    seed: int = 42
    price_volatility: float = 0.005
    imbalance_probability: float = 0.15
    protocols: List[str] = field(default_factory=lambda: [
        "uniswap_v2", "uniswap_v3", "sushiswap_v2",
        "curve_v1", "balancer_v2", "pancake_v2",
    ])


@dataclass
class StrategyConfig:
    enabled_strategies: List[str] = field(default_factory=lambda: [
        "cross_dex", "triangular", "flash_loan",
        "liquidation", "sandwich", "funding_rate", "mev_bundle",
    ])
    gas_price_gwei: float = 30.0
    eth_price_usd: float = 2500.0
    max_slippage_bps: int = 50
    min_profit_threshold: float = 1e-10


@dataclass
class TrainingConfig:
    algorithm: str = "ppo"
    total_timesteps: int = 1_000_000
    num_envs: int = 8
    action_mode: str = "discrete"
    episode_length: int = 1024
    learning_rate: float = 3e-4
    batch_size: int = 256
    gamma: float = 0.99
    gae_lambda: float = 0.95
    clip_range: float = 0.2
    ent_coef: float = 0.01
    vf_coef: float = 0.5
    max_grad_norm: float = 0.5
    network_arch: List[int] = field(default_factory=lambda: [512, 512, 256])
    eval_freq: int = 10_000
    eval_episodes: int = 10
    save_freq: int = 50_000
    device: str = "auto"


@dataclass
class ExecutionConfig:
    chain_id: int = 1
    rpc_endpoint: Optional[str] = None
    ws_endpoint: Optional[str] = None
    flashbots_relay: str = "https://relay.flashbots.net"
    private_key: Optional[str] = None
    max_gas_price_gwei: float = 100.0
    target_block_offset: int = 1
    tx_timeout_seconds: int = 30


@dataclass
class MonitoringConfig:
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 8050
    log_level: str = "INFO"
    metrics_export_interval: int = 60
    alert_pnl_threshold: float = -0.1
    prometheus_port: int = 9090


@dataclass
class Config:
    market: MarketConfig = field(default_factory=MarketConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    def to_dict(self) -> Dict:
        from dataclasses import asdict
        return asdict(self)

    def save(self, path: str):
        import json
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "Config":
        import json
        with open(path) as f:
            data = json.load(f)
        return cls(
            market=MarketConfig(**data.get("market", {})),
            strategy=StrategyConfig(**data.get("strategy", {})),
            training=TrainingConfig(**data.get("training", {})),
            execution=ExecutionConfig(**data.get("execution", {})),
            monitoring=MonitoringConfig(**data.get("monitoring", {})),
        )
