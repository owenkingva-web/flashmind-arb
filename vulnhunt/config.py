"""T3-3 Configuration - chains, keys, paths, settings."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).resolve().parent.parent / '.env'
load_dotenv(_env_path)

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'vulnhunt' / 'data'
LOG_DIR = PROJECT_ROOT / 'vulnhunt' / 'logs'
POC_DIR = PROJECT_ROOT / 'vulnhunt' / 'pocs'
DB_PATH = DATA_DIR / 'vulnhunt.db'
ALERTS_FILE = DATA_DIR / 'alerts.jsonl'
KNOWN_PROTOCOLS_FILE = DATA_DIR / 'known_protocols.json'

for d in [DATA_DIR, LOG_DIR, POC_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Wallet
WALLET_PRIVATE_KEY = os.getenv('WALLET_PRIVATE_KEY', '')

# API Keys
# Single Etherscan V2 API key works for ALL chains (including Base)
ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY', '')
ARBISCAN_API_KEY = os.getenv('ARBISCAN_API_KEY', ETHERSCAN_API_KEY)
BASESCAN_API_KEY = os.getenv('BASESCAN_API_KEY', ETHERSCAN_API_KEY)
BSCSCAN_API_KEY = os.getenv('BSCSCAN_API_KEY', ETHERSCAN_API_KEY)
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')

# Email Alerts (Gmail App Password)
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
ALERT_EMAIL_PASSWORD = os.getenv('ALERT_EMAIL_PASSWORD', '')
ALERT_EMAIL_TO = os.getenv('ALERT_EMAIL_TO', ALERT_EMAIL)

# Chain Configurations
# v3.0: Private node configuration
# Set these in .env for dedicated endpoints (lower latency, higher rate limits)
# Free tier Alchemy/Infura gives 300M compute units/month
PRIVATE_NODES = {
    1: os.getenv('RPC_MAINNET_PRIVATE', ''),      # Alchemy/Infura dedicated
    42161: os.getenv('RPC_ARBITRUM_PRIVATE', ''),    # Alchemy/Infura dedicated
    8453: os.getenv('RPC_BASE_PRIVATE', ''),         # Alchemy/Infura dedicated
    56: os.getenv('RPC_BSC_PRIVATE', ''),            # BSC dedicated node
}

# WebSocket endpoint for Arbitrum (sub-second block monitoring)
WS_ENDPOINTS = {
    42161: os.getenv('WS_ARBITRUM', ''),
}

CHAINS = {
    1: {
        'name': 'Ethereum',
        'short': 'eth',
        'rpc': PRIVATE_NODES[1] or os.getenv('RPC_MAINNET', 'https://eth.llamarpc.com'),
        'explorer_api': 'https://api.etherscan.io/v2/api',
        'explorer_url': 'https://etherscan.io',
        'api_key': ETHERSCAN_API_KEY,
        'chainid': 1,
        'block_time': 12,
        'native_token': 'ETH',
        'native_decimals': 18,
        'gas_price_gwei': 15,
        'flash_loan_providers': [
            {'name': 'Balancer', 'router': '0xBA12222222228d8Ba445958a75a0704d566BF2C8'},
            {'name': 'Aave V3', 'pool': '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2'},
        ],
    },
    42161: {
        'name': 'Arbitrum',
        'short': 'arb',
        'rpc': PRIVATE_NODES[42161] or os.getenv('RPC_ARBITRUM', 'https://arb1.arbitrum.io/rpc'),
        'explorer_api': 'https://api.etherscan.io/v2/api',
        'explorer_url': 'https://arbiscan.io',
        'api_key': ARBISCAN_API_KEY,
        'chainid': 42161,
        'block_time': 0.25,
        'native_token': 'ETH',
        'native_decimals': 18,
        'gas_price_gwei': 0.02,
        'flash_loan_providers': [
            {'name': 'Balancer', 'router': '0xBA12222222228d8Ba445958a75a0704d566BF2C8'},
            {'name': 'Aave V3', 'pool': '0x794a61358D6845594F94dc1DB02A252b5b4814aD'},
        ],
    },
    8453: {
        'name': 'Base',
        'short': 'base',
        'rpc': PRIVATE_NODES[8453] or os.getenv('RPC_BASE', 'https://mainnet.base.org'),
        'explorer_api': 'https://api.etherscan.io/v2/api',
        'explorer_url': 'https://basescan.org',
        'api_key': BASESCAN_API_KEY,
        'chainid': 8453,
        'block_time': 2,
        'native_token': 'ETH',
        'native_decimals': 18,
        'gas_price_gwei': 0.01,
        'flash_loan_providers': [
            {'name': 'Aave V3', 'pool': '0xA238Dd80C259a72e81d7e4664a9801593F98d1c5'},
        ],
    },
    56: {
        'name': 'BNB Chain',
        'short': 'bsc',
        'rpc': PRIVATE_NODES[56] or 'https://bsc-dataseed.binance.org',
        'explorer_api': 'https://api.etherscan.io/v2/api',
        'explorer_url': 'https://bscscan.com',
        'api_key': BSCSCAN_API_KEY,
        'chainid': 56,
        'block_time': 3,
        'native_token': 'BNB',
        'native_decimals': 18,
        'gas_price_gwei': 1,
        'flash_loan_providers': [
            {'name': 'PancakeSwap', 'router': '0x10ED43C718714eb63d5aA57B78B54704E256024E'},
        ],
    },
}

# Protocols to skip (well-audited, battle-tested)
KNOWN_SAFE_PROTOCOLS = {
    'aave-v3', 'aave-v2', 'compound-v3', 'compound-v2',
    'uniswap-v3', 'uniswap-v2', 'curve-dex', 'curve-finance',
    'makerdao', 'lido', 'rocket-pool', 'pendle',
    'balancer-v2', 'balancer-v1', 'sushi', '1inch',
    'convex-finance', 'yearn-finance', 'synthetix', 'dydx', 'gmx',
    'pancakeswap', 'trader-joe', 'camelot', 'spark', 'morpho',
    'eigenlayer', 'ethena', 'usds', 'frax', 'liquity',
    'stargate', 'benqi', 'radiant', 'compound', 'aave',
    'makerdao', 'uniswap', 'sushiswap', 'pancakeswap-amm',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

DEFAULT_SCAN = {
    'min_tvl': 0,
    'max_tvl': 50_000_000,  # v3.1: Include mid-cap too (was 5M, now 50M)
    'days_old': 365,  # v3.1: Scan protocols up to 1 year old (was 90)
    'min_source_lines': 20,
    'confidence_threshold': 0.3,
    'etherscan_rate_limit': 0.2,  # v3.1: Faster rate (was 0.25)
    'discovery_interval': 30,  # v3.1: Every 30s instead of 60s
}

# NOTE: ETH_PRICE_USD=2400 is a stale default. In production, use get_eth_price()
# which fetches from CoinGecko with a TTL cache, falling back to this value.
ETH_PRICE_USD = 2400

# Active chains — all configured chains
ACTIVE_CHAIN_IDS = [42161, 8453, 56, 1]


# ── Dynamic ETH price with TTL cache ────────────────────────────────────────
_eth_price_cache = {'price': ETH_PRICE_USD, 'timestamp': 0}
_ETH_PRICE_TTL = 60  # seconds


def get_eth_price() -> float:
    """Get a fresh ETH/USD price from CoinGecko (with TTL cache).

    Falls back to the hardcoded ETH_PRICE_USD on any failure.
    Cache duration: 60 seconds.
    """
    import time as _time
    now = _time.time()
    if now - _eth_price_cache['timestamp'] < _ETH_PRICE_TTL:
        return _eth_price_cache['price']

    try:
        import requests as _requests
        coingecko_key = os.getenv('COINGECKO_API_KEY', '')
        headers = {}
        if coingecko_key:
            headers['x-cg-demo-api-key'] = coingecko_key
        resp = _requests.get(
            'https://api.coingecko.com/api/v3/simple/price',
            params={'ids': 'ethereum', 'vs_currencies': 'usd'},
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            price = resp.json()['ethereum']['usd']
            _eth_price_cache['price'] = price
            _eth_price_cache['timestamp'] = now
            return price
    except Exception:
        pass

    # Fallback to stale value — don't retry for another TTL
    _eth_price_cache['timestamp'] = now
    return _eth_price_cache['price']


SETTINGS = {
    'chains': CHAINS,
    'active_chain_ids': ACTIVE_CHAIN_IDS,
    'eth_price_usd': ETH_PRICE_USD,
    'default_scan': DEFAULT_SCAN,
    'known_safe_protocols': KNOWN_SAFE_PROTOCOLS,
    'wallet_private_key': WALLET_PRIVATE_KEY,
    'data_dir': DATA_DIR,
    'log_dir': LOG_DIR,
    'poc_dir': POC_DIR,
    'db_path': DB_PATH,
}
