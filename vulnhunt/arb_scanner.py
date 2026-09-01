r"""T3-3 Cross-Chain Arbitrage Price Scanner

Monitors token prices on DEXes across all 4 chains via V2 getReserves()
and V3 slot0.sqrtPriceX96. Flags opportunities where spread > 0.5%.
"""
import asyncio
import time
from web3 import Web3

from .config import CHAINS, ETH_PRICE_USD
from .db import Database


TOKENS = {
    'WETH': {1: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
             42161: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1',
             8453: '0x4200000000000000000000000000000000000006',
             56: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'},
    'USDC': {1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
             42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
             8453: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
             56: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d'},
    'USDT': {1: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
             42161: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',
             8453: '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb',
             56: '0x55d398326f99059fF775485246999027B3197955'},
    'WBTC': {1: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
             42161: '0x2f2a2543B76A416ed4D6FB9605fA246f22Ca60C1',
             8453: '0xCd6Fa8b34c52C84835b44e7ae3c5cC0F9a0377Ca',
             56: '0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c'},
}

V2_POOLS = {
    (1, 'WETH', 'USDC'): '0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc',
    (1, 'WETH', 'USDT'): '0x0d4a11d5EEaaC28EC3F61d100daF4d40471f952e',
    (1, 'WETH', 'WBTC'): '0xBb2b8038a1640196FbE3e38816F3e67Cba72D940',
    (42161, 'WETH', 'USDC'): '0xCBCdF9626bC03E24f779434178A73a0B4bad62eD',
    (56, 'WETH', 'USDT'): '0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE',
}

V3_POOLS = {
    (1, 'WETH', 'USDC', 500): '0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640',
    (1, 'WETH', 'USDC', 3000): '0x8ad599c3A0ff1De0820eF2C5D69D86921B4F3F62',
    (1, 'WETH', 'USDT', 500): '0x3416cF6C708Da44DB2624D63ea0AAef7113527C6',
    (42161, 'WETH', 'USDC', 3000): '0xC6962004f452bE9203591991D15f6b388e09E8D0',
    (8453, 'WETH', 'USDC', 100): '0x6c6Bc977E13Df9b0de53b251522280BB72383700',
}

V2_ABI = '[{"inputs":[],"name":"getReserves","outputs":[{"name":"","type":"uint128"},{"name":"","type":"uint128"},{"name":"","type":"uint32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"}]'

V3_ABI = '[{"inputs":[],"name":"slot0","outputs":[{"name":"sqrtPriceX96","type":"uint160"},{"name":"tick","type":"int24"},{"name":"","type":"uint16"},{"name":"","type":"uint16"},{"name":"","type":"uint16"},{"name":"","type":"uint8"},{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"stateMutability":"view","type":"function"}]'

BRIDGE_COST = {(1,42161):5,(42161,1):5,(1,8453):3,(8453,1):3,(1,56):8,(56,1):8,
               (42161,8453):2,(8453,42161):2,(42161,56):6,(56,42161):6,(8453,56):6,(56,8453):6}
MIN_SPREAD_PCT = 0.5


class ArbScanner:
    """Cross-chain arbitrage price scanner."""

    def __init__(self, db: Database):
        self.db = db
        self._w3: dict[int, Web3] = {}
        self._ct: dict = {}
        self._t0: dict = {}
        self._running = False

    def _get_w3(self, cid: int) -> Web3:
        if cid not in self._w3:
            self._w3[cid] = Web3(Web3.HTTPProvider(CHAINS.get(cid,{}).get('rpc',''), request_kwargs={'timeout':15}))
        return self._w3[cid]

    def _get_ct(self, cid: int, addr: str, abi: str):
        k = f"{cid}:{addr.lower()}:{abi[:10]}"
        if k not in self._ct:
            self._ct[k] = self._get_w3(cid).eth.contract(address=Web3.to_checksum_address(addr), abi=abi)
        return self._ct[k]

    def get_token_price(self, chain_id: int, token: str, dex: str) -> float:
        try:
            return self._v2_price(chain_id, token) if dex == 'uniswap_v2' else self._v3_price(chain_id, token)
        except Exception as e:
            print(f'[ARB] Price error {token}@{chain_id}/{dex}: {e}')
        return 0.0

    def _v2_price(self, cid: int, token: str) -> float:
        for quote in ['USDC', 'USDT']:
            addr = V2_POOLS.get((cid, token, quote)) or V2_POOLS.get((cid, quote, token))
            if not addr: continue
            r0, r1, _ = self._get_ct(cid, addr, V2_ABI).functions.getReserves().call()
            if r0 == 0 or r1 == 0: continue
            tk = f"{cid}:{addr.lower()}:t0"
            if tk not in self._t0:
                self._t0[tk] = self._get_ct(cid, addr, V2_ABI).functions.token0().call().lower()
            t_addr = TOKENS.get(token, {}).get(cid, '').lower()
            rt, rq = (r0, r1) if self._t0[tk] == t_addr else (r1, r0)
            return (rq / 10**(6 if quote == 'USDC' else 18)) / (rt / 1e18)
        return float(ETH_PRICE_USD) if token == 'WETH' and cid in CHAINS else 0.0

    def _v3_price(self, cid: int, token: str) -> float:
        for quote in ['USDC', 'USDT']:
            for fee in [500, 3000, 10000]:
                addr = V3_POOLS.get((cid, token, quote, fee)) or V3_POOLS.get((cid, quote, token, fee))
                if not addr: continue
                sqrt_p = self._get_ct(cid, addr, V3_ABI).functions.slot0().call()[0]
                price = (sqrt_p / 2**96) ** 2
                tk = f"{cid}:{addr.lower()}:t0"
                if tk not in self._t0:
                    self._t0[tk] = self._get_ct(cid, addr, V3_ABI).functions.token0().call().lower()
                if self._t0[tk] == TOKENS.get(quote, {}).get(cid, '').lower():
                    price = 1.0 / price if price > 0 else 0
                return price * 10**(18 - (6 if quote == 'USDC' else 18))
        return 0.0

    def calculate_profit(self, opp: dict) -> float:
        bc, sc = opp.get('buy_chain', 0), opp.get('sell_chain', 0)
        costs = ((CHAINS.get(bc,{}).get('gas_price_gwei',1) * 500000 / 1e9) * ETH_PRICE_USD
                 if bc == sc else 2.0 + BRIDGE_COST.get((bc, sc), 5.0))
        return max(0.0, 10000 * opp.get('spread_pct', 0) / 100 - costs)

    def scan_all(self) -> list:
        prices: dict = {}
        for (cid, ta, tb), addr in V2_POOLS.items():
            for tok in [ta, tb]:
                if tok in ('USDC', 'USDT') or (cid, tok, 'uniswap_v2') in prices: continue
                try:
                    p = self._v2_price(cid, tok)
                    if p > 0: prices[(cid, tok, 'uniswap_v2')] = p
                except Exception: pass
        for (cid, ta, tb, _), addr in V3_POOLS.items():
            for tok in [ta, tb]:
                if tok in ('USDC', 'USDT') or (cid, tok, 'uniswap_v3') in prices: continue
                try:
                    p = self._v3_price(cid, tok)
                    if p > 0: prices[(cid, tok, 'uniswap_v3')] = p
                except Exception: pass
        by_tok: dict[str, list] = {}
        for (cid, tok, dex), price in prices.items():
            by_tok.setdefault(tok, []).append({'price': price, 'chain_id': cid, 'dex': dex})
        opps = []
        for tok, entries in by_tok.items():
            if len(entries) < 2: continue
            entries.sort(key=lambda x: x['price'])
            lo, hi = entries[0], entries[-1]
            if lo['price'] == 0: continue
            spread = ((hi['price'] - lo['price']) / lo['price']) * 100
            if spread <= MIN_SPREAD_PCT: continue
            opp = {'token': tok, 'buy_chain': lo['chain_id'], 'sell_chain': hi['chain_id'],
                   'buy_dex': lo['dex'], 'sell_dex': hi['dex'], 'buy_price': lo['price'],
                   'sell_price': hi['price'], 'spread_pct': round(spread, 3),
                   'net_profit_usd': 0.0, 'timestamp': time.time()}
            opp['net_profit_usd'] = self.calculate_profit(opp)
            if opp['net_profit_usd'] > 0:
                opps.append(opp)
                bsn = CHAINS.get(lo['chain_id'],{}).get('short','?')
                ssn = CHAINS.get(hi['chain_id'],{}).get('short','?')
                print(f'[ARB] {tok}: {lo["dex"]}({bsn})->{hi["dex"]}({ssn}) spread={spread:.2f}% ${opp["net_profit_usd"]:.2f}')
        for o in opps:
            self.db.log_execution(contract_address=TOKENS.get(o['token'],{}).get(o['buy_chain'],''),
                                  chain_id=o['buy_chain'], action='arb_opportunity',
                                  profit_eth=o['net_profit_usd']/ETH_PRICE_USD,
                                  profit_usd=o['net_profit_usd'], metadata=o)
        return opps

    async def run(self, interval: float = 10.0):
        self._running = True
        print(f'[ARB] Starting (every {interval}s)')
        while self._running:
            try: self.scan_all()
            except Exception as e: print(f'[ARB] Error: {e}')
            await asyncio.sleep(interval)

    def stop(self):
        self._running = False
