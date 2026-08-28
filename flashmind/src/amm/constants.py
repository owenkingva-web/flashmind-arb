"""
FlashMind — AMM Constants & Protocol Definitions
=================================================
Protocol identifiers, fee tiers, and standard parameters for every
supported AMM type.  Keep this as the single source of truth so every
strategy, environment, and data module imports from here.
"""

# ---------------------------------------------------------------------------
# Protocol identifiers
# ---------------------------------------------------------------------------
UNISWAP_V2 = "uniswap_v2"
UNISWAP_V3 = "uniswap_v3"
SUSHISWAP_V2 = "sushiswap_v2"
CURVE_V1 = "curve_v1"
BALANCER_V2 = "balancer_v2"
PANCAKE_V2 = "pancake_v2"
PANCAKE_V3 = "pancake_v3"
SPIRIT_V3 = "spirit_v3"

ALL_PROTOCOLS = [
    UNISWAP_V2, UNISWAP_V3, SUSHISWAP_V2,
    CURVE_V1, BALANCER_V2, PANCAKE_V2, PANCAKE_V3, SPIRIT_V3,
]

# ---------------------------------------------------------------------------
# Fee tiers (basis points — 100 bps = 1 %)
# ---------------------------------------------------------------------------
# Uniswap V2 clones (constant 0.30 %)
V2_FEE_BPS = 30

# Uniswap V3 / V3-clone fee tiers
V3_FEE_TIERS_BPS = [1, 5, 30, 100, 1000]  # 0.01%, 0.05%, 0.30%, 1%, 10%

# Curve stable-swap fee (typically 4 bps but configurable)
CURVE_FEE_BPS = 4

# Balancer V2 (pool-dependent; we store common defaults)
BALANCER_FEE_TIERS_BPS = [10, 30, 100, 300, 1000]

# Flash loan fee tiers (bps) — deducted from borrowed amount on return
FLASH_LOAN_FEE_BPS = {
    UNISWAP_V2: 30,          # V2-style flash swap
    UNISWAP_V3: 30,          # V3 flash swap
    BALANCER_V2: 0,          # Balancer flash loan is free (gas only)
    CURVE_V1: 0,             # Curve flash loan (implementation-dependent)
    "aave_v3": 5,            # Aave V3: 0.05 % for non-EMode
    "dydx_v3": 0,            # dYdX: 0 % (theoretical; they use funding)
}

# ---------------------------------------------------------------------------
# Chain defaults
# ---------------------------------------------------------------------------
MAINNET = 1
ARBITRUM = 42161
OPTIMISM = 10
POLYGON = 137
BASE = 8453
BNB_CHAIN = 56
AVALANCHE = 43114

CHAIN_NAMES = {
    MAINNET: "ethereum",
    ARBITRUM: "arbitrum",
    OPTIMISM: "optimism",
    POLYGON: "polygon",
    BASE: "base",
    BNB_CHAIN: "bnb",
    AVALANCHE: "avalanche",
}

# ---------------------------------------------------------------------------
# Token symbols used throughout the simulation
# ---------------------------------------------------------------------------
STABLECOINS = ("USDT", "USDC", "DAI", "BUSD", "FRAX", "TUSD", "USDP", "LUSD")
MAJOR_TOKENS = ("WETH", "WBTC", "USDT", "USDC", "DAI", "ARB", "OP", "BNB")

# ---------------------------------------------------------------------------
# Gas constants (in native-wei units where relevant; we mostly use Gwei)
# ---------------------------------------------------------------------------
GWEI = 1e9
DEFAULT_GAS_PRICE_GWEI = 30       # 30 Gwei fallback
FLASH_LOAN_GAS_OVERHEAD = 150_000  # extra gas for flash callback
SWAP_GAS_BASE = 130_000            # typical single-swap gas
APPROVE_GAS = 50_000

# ---------------------------------------------------------------------------
# Slippage safety constants
# ---------------------------------------------------------------------------
MAX_SLIPPAGE_BPS = 50              # 0.5 % max allowed slippage
MIN_PROFIT_WEI_THRESHOLD = 1e-6    # 0.000001 in token units — ignore dust profits
