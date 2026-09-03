"""T3-3 Autonomous Vulnerability Hunter v3.2

Zero-capital DeFi vulnerability discovery and exploitation system.
28 modules: discovery, analysis, PoC, fork validation, execution,
real-time monitoring (upgrades, mempool, governance, init hunting),
MEV (sandwich, liquidation, arbitrage).
"""
__version__ = '3.2.0'

from .config import CHAINS, WALLET_PRIVATE_KEY, ETH_PRICE_USD, DEFAULT_SCAN, SETTINGS
from .db import Database
from .discovery import DiscoveryEngine
from .fetcher import SourceFetcher
from .analyzer import VulnerabilityAnalyzer, Finding
from .prober import OnChainProber
from .governance import GovernanceScanner
from .assessor import ExploitabilityAssessor
from .poc_generator import PoCGenerator
from .fork_validator import ForkValidator
from .executor import ExploitExecutor
from .alerts import AlertManager
from .agent import HunterAgent
from .upgrade_monitor import UpgradeMonitor
from .init_hunter import InitHunter
from .sandwich_bot import SandwichBot
from .liquidation_hunter import LiquidationHunter
from .arb_scanner import ArbScanner

# Compatibility aliases for code that imports under alternate names
# (Phase 8-10 modules may use these)
GovernanceMonitor = GovernanceScanner
Alerter = AlertManager
TxExecutor = ExploitExecutor
WsDiscovery = None  # ws_discovery.WebSocketDiscovery loaded lazily

__all__ = [
    'CHAINS', 'WALLET_PRIVATE_KEY', 'ETH_PRICE_USD', 'DEFAULT_SCAN', 'SETTINGS',
    'Database', 'DiscoveryEngine', 'SourceFetcher',
    'VulnerabilityAnalyzer', 'Finding', 'OnChainProber',
    'GovernanceScanner', 'ExploitabilityAssessor',
    'PoCGenerator', 'ForkValidator', 'ExploitExecutor',
    'AlertManager', 'HunterAgent',
    'UpgradeMonitor', 'InitHunter',
    'SandwichBot', 'LiquidationHunter', 'ArbScanner',
    # Compatibility aliases
    'GovernanceMonitor', 'Alerter', 'TxExecutor', 'WsDiscovery',
]
