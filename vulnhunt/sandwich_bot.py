r"""T3-3 Sandwich Attack Bot - Monitors DEX mempools for large swaps and front-runs them.

Supports Uniswap V2/V3, Camelot, SushiSwap, Aerodrome, PancakeSwap.
Uses eth_subscribe when available, falls back to pending block polling.
"""
import asyncio
import json
from typing import Optional
from web3 import Web3

from .config import CHAINS
from .db import Database


# DEX swap selectors and router addresses
SWAP_SELECTORS = {
    '0x38ed1739': 'swapExactTokensForTokens', '0x7ff36ab5': 'swapExactTokensForETH',
    '0x18cbafe5': 'swapExactETHForTokens', '0x8803dbee': 'swapTokensForExactTokens',
    '0x414bf389': 'exactInputSingle', '0xc04b8d59': 'exactInput',
    '0x04e45aaf': 'exactOutputSingle', '0x7c025200': 'swap',
    '0xfb3bdb41': 'swapExactTokensForTokensSupportingFeeOnTransferTokens',
}
DEX_ROUTERS = {
    '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'uniswap_v2',
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'uniswap_v3',
    '0xe592427a0aece92de3edee1f18e0157c05861564': 'uniswap_v3',
    '0x1a3c9b1d2e05ea3a83e561c3e5e4b25a3fbea96e': 'camelot',
    '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f': 'sushiswap',
    '0x10ed43c718714eb63d5aa57b78b54704e256024e': 'pancakeswap',
    '0x13f4ea83d0bd40e75c8222255bc855a974568dd4': 'pancakeswap_v3',
    '0xcf77a3ba9a5243b8026811679abbd0ccb0c1794e': 'aerodrome',
}
MIN_PROFIT_ETH = 0.001
CHAIN_PRIORITY = [42161, 8453, 56, 1]


def _to_hex(val) -> str:
    if isinstance(val, bytes):
        return '0x' + val.hex()
    return val or ''


class SandwichBot:
    """MEV sandwich attack bot monitoring mempool for large DEX swaps."""

    def __init__(self, db: Database):
        self.db = db
        self._w3_cache: dict[int, Web3] = {}
        self._running = False
        self._seen: dict[int, set] = {}

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            rpc = CHAINS.get(chain_id, {}).get('rpc', '')
            self._w3_cache[chain_id] = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 15}))
        return self._w3_cache[chain_id]

    def _decode_swap(self, calldata: str) -> Optional[dict]:
        if len(calldata) < 10:
            return None
        func = SWAP_SELECTORS.get(calldata[:10])
        if not func:
            return None
        d = bytes.fromhex(calldata[2:])
        r = {'selector': calldata[:10], 'function': func}
        try:
            if func == 'exactInputSingle' and len(d) >= 164:
                r.update(token_in='0x'+d[4:24].hex(), token_out='0x'+d[36:56].hex(),
                         amount_in=int.from_bytes(d[100:132], 'big'),
                         fee=int.from_bytes(d[56:60], 'big'))
                return r
            if func == 'swapExactTokensForTokens' and len(d) >= 132:
                r['amount_in'] = int.from_bytes(d[4:36], 'big')
                off = int.from_bytes(d[68:100], 'big')
                if len(d) >= off + 64:
                    plen = int.from_bytes(d[off+32:off+64], 'big')
                    r['path'] = ['0x'+d[off+64+i*32+12:off+64+i*32+32].hex()
                                for i in range(min(plen, 4)) if off+64+i*32+32 <= len(d)]
                return r
            if func == 'swap' and len(d) >= 196:
                r.update(recipient='0x'+d[4:24].hex(), amount_in=int.from_bytes(d[100:132], 'big'))
                return r
        except Exception as e:
            print(f'[SANDWICH] Decode error: {e}')
        return None

    def estimate_profit(self, swap_tx: dict, chain_id: int) -> float:
        try:
            cd = _to_hex(swap_tx.get('input', swap_tx.get('data', '0x')))
            dec = self._decode_swap(cd)
            if not dec or dec.get('amount_in', 0) == 0:
                return 0.0
            gas_cost = ((swap_tx.get('gasPrice', 0) or 0) * 300_000) / 1e18
            return max(0.0, (dec['amount_in'] / 1e18) * 0.003 - gas_cost)
        except Exception as e:
            print(f'[SANDWICH] Profit error: {e}')
            return 0.0

    def build_sandwich(self, swap_tx: dict, chain_id: int) -> dict:
        cd = _to_hex(swap_tx.get('input', swap_tx.get('data', '0x')))
        dec = self._decode_swap(cd)
        if not dec:
            return {'error': 'Cannot decode swap'}
        to = _to_hex(swap_tx.get('to', ''))
        gas = swap_tx.get('gasPrice', 0) or 0
        profit = self.estimate_profit(swap_tx, chain_id)
        return {
            'chain_id': chain_id,
            'target_tx': _to_hex(swap_tx.get('hash', b'')),
            'router': to, 'dex': DEX_ROUTERS.get(to.lower(), 'unknown'),
            'decoded_swap': dec, 'front_run_gas': int(gas * 1.1) + 1,
            'back_run_gas': gas, 'estimated_profit_eth': profit,
            'profitable': profit > MIN_PROFIT_ETH,
        }

    def _is_dex_swap(self, tx: dict) -> bool:
        to = _to_hex(tx.get('to', ''))
        if to.lower() not in DEX_ROUTERS:
            return False
        data = _to_hex(tx.get('input', tx.get('data', '0x')))
        return data[:10] in SWAP_SELECTORS

    async def _process_tx(self, chain_id: int, tx: dict):
        tx_hash = _to_hex(tx.get('hash', b''))
        if not tx_hash:
            return
        seen = self._seen.setdefault(chain_id, set())
        if tx_hash in seen:
            return
        seen.add(tx_hash)
        if len(seen) > 50000:
            self._seen[chain_id] = set(list(seen)[-25000:])
        if not self._is_dex_swap(tx):
            return
        profit = self.estimate_profit(tx, chain_id)
        if profit < MIN_PROFIT_ETH:
            return
        sw = self.build_sandwich(tx, chain_id)
        if sw.get('profitable'):
            print(f'[SANDWICH] {profit:.4f} ETH chain={chain_id} dex={sw.get("dex","?")} tx={tx_hash[:16]}...')
            self.db.log_execution(contract_address=sw.get('router', ''), chain_id=chain_id,
                                  action='sandwich_detected', tx_hash=tx_hash,
                                  profit_eth=profit, metadata=sw)

    async def monitor_mempool(self, chain_id: int):
        """Monitor pending txs. WS eth_subscribe first, poll fallback."""
        w3 = self._get_w3(chain_id)
        name = CHAINS.get(chain_id, {}).get('name', str(chain_id))
        ws_url = CHAINS.get(chain_id, {}).get('rpc', '').replace('https://', 'wss://').replace('http://', 'ws://')
        while self._running:
            try:
                import websockets
                async with websockets.connect(ws_url, ping_interval=20) as ws:
                    await ws.send(json.dumps({'jsonrpc': '2.0', 'method': 'eth_subscribe',
                                             'params': ['newPendingTransactions'], 'id': 1}))
                    await ws.recv()
                    print(f'[SANDWICH] WS sub on {name}')
                    while self._running:
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=30)
                            th = json.loads(msg).get('params', {}).get('result', '')
                            if th:
                                try:
                                    tx = w3.eth.get_transaction(th)
                                    if tx: await self._process_tx(chain_id, tx)
                                except Exception: pass
                        except asyncio.TimeoutError: continue
                        except Exception: break
            except Exception: pass
            print(f'[SANDWICH] Polling fallback on {name}')
            while self._running:
                try:
                    blk = w3.eth.get_block('pending', full_transactions=True)
                    if blk and blk.transactions:
                        for tx in blk.transactions:
                            await self._process_tx(chain_id, tx)
                except Exception: pass
                await asyncio.sleep(0.5)

    async def start(self, chain_ids: list = None):
        if chain_ids is None:
            chain_ids = CHAIN_PRIORITY
        self._running = True
        tasks = [asyncio.create_task(self.monitor_mempool(c)) for c in chain_ids]
        print(f'[SANDWICH] Started on {len(tasks)} chains')
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self):
        self._running = False
