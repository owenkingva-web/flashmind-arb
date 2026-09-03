r"""T3-3 Mempool Monitoring Module

Real-time monitoring of pending transactions to detect:
1. Other hunters deploying to the same target (race condition)
2. Exploit transactions being submitted (information)
3. Liquidation opportunities
4. Large DEX swaps that could create oracle manipulation windows
5. Governance proposal executions

Uses WebSocket subscriptions where available, falls back to polling.
"""
import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable
from web3 import Web3
from collections import OrderedDict

import websockets
import requests

from .config import CHAINS


@dataclass
class MempoolEvent:
    event_type: str  # 'pending_tx', 'large_swap', 'governance_exec', 'liquidation', 'exploit_detected'
    chain_id: int
    tx_hash: str
    from_address: str
    to_address: str = ""
    value: int = 0
    gas_price: int = 0
    data: str = ""
    decoded_info: dict = field(default_factory=dict)
    timestamp: float = 0
    priority: int = 0  # 0=info, 1=medium, 2=high, 3=critical

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()


# Known attacker/hunter addresses (populated from historical exploit data)
# NOTE: This set should be populated from on-chain data / MEV bot registries.
# Currently minimal — integrate with Flashbots/builder-boost data for production.
KNOWN_HUNTERS = {
    # Add known MEV bots and whitehat hunters
    # These are public addresses from public exploit analyses
    '0x000000000035B5e5A6214B28aC8DFFaA2AFA0eE8',  # Flashbots relay
    '0x388C818CA8B9251b393131C08a736A67ccB19297',  # MEV Blocker
}

# Function selectors for interesting operations
CRITICAL_SELECTORS = {
    # Flash loan callbacks
    '0x6c18f570': 'onFlashLoan',
    '0x21551d51': 'receiveFlashLoan',
    # Governance
    '0x7d645f4f': 'castVote',
    '0xc7e284d8': 'queue',
    '0x5c11d795': 'execute',
    '0x4e71d92d': 'createProposal',
    # Dangerous admin
    '0xf2fde38b': 'transferOwnership',
    '0x3659cfe6': 'upgradeTo',
    '0x8f283970': 'withdrawAll',
    '0x3ccfd60b': 'sweep',
    # Selfdestruct
    '0x42966c68': 'selfdestruct',
    # Reentrancy-prone
    '0x2e1a7d4d': 'withdraw',
    '0x3ccfd60b': 'withdraw',
    '0xa9059cbb': 'transfer',
    '0x23b872dd': 'transferFrom',
}

# DEX router addresses for detecting swaps (all lowercase for .lower() comparison)
DEX_ROUTERS = {
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',  # Uniswap V3 Router
    '0xe592427a0aece92de3edee1f18e0157c05861564',  # Uniswap V3 Router 2
    '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',  # Uniswap V2 Router
    '0x1111111254eeb25477b68fb85ed929f73a960582',  # 1inch
    '0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f',  # Sushi
    '0x13f4ea83d0bd40e75c8222255bc855a974568dd4',  # PancakeSwap V3
    '0x1b81d678ffb9c0263b24a97847620c99d213eb14',  # PancakeSwap V3 2
}


class MempoolMonitor:
    """Real-time mempool monitoring for competitive intelligence."""

    def __init__(self, event_callback: Optional[Callable[[MempoolEvent], Awaitable[None]]] = None):
        self._w3_cache = {}
        self._running = False
        self._callbacks = [event_callback] if event_callback else []
        self._recent_txs: dict[int, OrderedDict] = {}  # chain -> OrderedDict of tx_hash->True (insertion-ordered)
        self._target_watch = {}  # chain -> set of addresses we're watching
        self._suspicious_txs = []  # Recent suspicious transactions
        self._max_suspicious = 1000

    def add_callback(self, cb: Callable[[MempoolEvent], Awaitable[None]]):
        self._callbacks.append(cb)

    def watch_address(self, chain_id: int, address: str):
        """Watch for transactions involving a specific address."""
        if chain_id not in self._target_watch:
            self._target_watch[chain_id] = set()
        self._target_watch[chain_id].add(address.lower())

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id, {})
            rpc = chain.get('rpc', '')
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 30}))
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    async def _emit(self, event: MempoolEvent):
        for cb in self._callbacks:
            try:
                await cb(event)
            except Exception as e:
                print(f'[MEMPOOL] Callback error: {e}')

    def _analyze_tx(self, chain_id: int, tx: dict) -> Optional[MempoolEvent]:
        """Analyze a pending transaction for interesting patterns."""
        tx_hash = tx.get('hash', b'').hex() if isinstance(tx.get('hash'), bytes) else tx.get('hash', '')
        from_addr = tx.get('from', '')
        to_addr = tx.get('to', '')
        value = tx.get('value', 0)
        gas_price = tx.get('gasPrice', 0)
        data = tx.get('input', tx.get('data', '0x'))

        if isinstance(data, bytes):
            data = '0x' + data.hex() if data else '0x'

        # Dedup (OrderedDict preserves insertion order)
        if chain_id in self._recent_txs and tx_hash in self._recent_txs[chain_id]:
            return None
        if chain_id not in self._recent_txs:
            self._recent_txs[chain_id] = OrderedDict()
        self._recent_txs[chain_id][tx_hash] = True

        # Trim dedup cache (keep last 10000 by insertion order)
        if len(self._recent_txs[chain_id]) > 10000:
            # Evict oldest entries (first 5000)
            for _ in range(5000):
                self._recent_txs[chain_id].popitem(last=False)

        event = MempoolEvent(
            event_type='pending_tx',
            chain_id=chain_id,
            tx_hash=tx_hash,
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            gas_price=gas_price,
            data=data,
        )

        # Check 1: Transaction to a watched target
        watched = self._target_watch.get(chain_id, set())
        if to_addr and to_addr.lower() in watched:
            event.event_type = 'target_interaction'
            event.priority = 3  # CRITICAL - someone is interacting with our target
            event.decoded_info['reason'] = 'Transaction to watched target'
            self._suspicious_txs.append(event)
            return event

        # Check 2: Known hunter/attacker address
        if from_addr.lower() in KNOWN_HUNTERS:
            event.priority = 2
            event.decoded_info['reason'] = 'From known MEV bot/hunter'
            self._suspicious_txs.append(event)
            return event

        # Check 3: Function selector analysis
        selector = data[:10] if len(data) >= 10 else '0x'
        if selector in CRITICAL_SELECTORS:
            func_name = CRITICAL_SELECTORS[selector]
            event.decoded_info['function'] = func_name

            if 'withdraw' in func_name or 'sweep' in func_name:
                event.event_type = 'exploit_detected'
                event.priority = 3
                event.decoded_info['reason'] = f'Large {func_name} call'
            elif 'execute' in func_name or 'queue' in func_name:
                event.event_type = 'governance_exec'
                event.priority = 2
            elif 'Ownership' in func_name or 'upgrade' in func_name:
                event.event_type = 'governance_exec'
                event.priority = 2
            elif 'FlashLoan' in func_name:
                event.event_type = 'flash_loan_activity'
                event.priority = 1

            self._suspicious_txs.append(event)
            return event

        # Check 4: DEX swap (large value indicates potential oracle manipulation)
        if to_addr and to_addr.lower() in DEX_ROUTERS:
            if value > 0:
                event.event_type = 'large_swap'
                # Priority based on value
                eth_value = value / 1e18
                if eth_value > 100:
                    event.priority = 3  # $240K+ swap
                elif eth_value > 10:
                    event.priority = 2  # $24K+ swap
                else:
                    event.priority = 1
                event.decoded_info['eth_value'] = eth_value
                event.decoded_info['reason'] = f'DEX swap: {eth_value:.2f} ETH'
                if event.priority >= 2:
                    self._suspicious_txs.append(event)
                    return event

        # Check 5: High gas price (arbitrage/exploit urgency indicator)
        if gas_price > 50 * 1e9:  # > 50 gwei
            event.priority = max(event.priority, 1)
            event.decoded_info['high_gas'] = True

        return event if event.priority >= 2 else None

    async def poll_pending_pool(self, chain_id: int, interval: float = 2.0):
        """Poll the pending transaction pool.

        Uses eth_getBlockByNumber('pending') which returns all pending txs.
        Falls back to txpool_content if available.
        """
        w3 = self._get_w3(chain_id)
        chain_name = CHAINS.get(chain_id, {}).get('name', str(chain_id))
        print(f'[MEMPOOL] Starting poll on {chain_name} (every {interval}s)')

        while self._running:
            try:
                # Method 1: Get pending block transactions
                try:
                    pending = w3.eth.get_block('pending', full_transactions=True)
                    if pending and pending.transactions:
                        for tx in pending.transactions:
                            event = self._analyze_tx(chain_id, tx)
                            if event:
                                await self._emit(event)
                except Exception:
                    pass

                # Method 2: txpool_content (Geth-specific)
                try:
                    pool = w3.provider.make_request('txpool_content', [])
                    if pool and isinstance(pool, dict) and 'result' in pool:
                        for addr_group in pool['result'].values():
                            for nonce_group in addr_group.values():
                                for tx_data in nonce_group.values():
                                    event = self._analyze_tx(chain_id, tx_data)
                                    if event:
                                        await self._emit(event)
                except Exception:
                    pass

            except Exception as e:
                print(f'[MEMPOOL] Error polling {chain_name}: {e}')

            await asyncio.sleep(interval)

    async def monitor_websocket(self, chain_id: int, ws_url: str = None):
        """Monitor via WebSocket newHeads subscription for block timing + pending txs.

        Some providers (Alchemy, Infura dedicated) support pending tx
        WebSocket subscriptions. This is faster than polling.
        """
        chain = CHAINS.get(chain_id, {})
        rpc = chain.get('rpc', '')

        # Convert HTTP to WS if possible
        if not ws_url:
            ws_url = rpc.replace('https://', 'wss://').replace('http://', 'ws://')

        chain_name = chain.get('name', str(chain_id))
        print(f'[MEMPOOL] WebSocket connect to {chain_name}: {ws_url}')

        while self._running:
            try:
                async with websockets.connect(ws_url, ping_interval=30) as ws:
                    # Subscribe to new pending transactions
                    await ws.send(json.dumps({
                        'jsonrpc': '2.0',
                        'method': 'eth_subscribe',
                        'params': ['newPendingTransactions', True],
                        'id': 1,
                    }))
                    response = await ws.recv()
                    sub_id = json.loads(response).get('result', '')
                    print(f'[MEMPOOL] Subscribed to pending txs on {chain_name}')

                    while self._running:
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=30)
                            data = json.loads(msg)
                            if 'params' in data:
                                tx_hash = data['params'].get('result', '')
                                if tx_hash:
                                    # Fetch full tx details
                                    w3 = self._get_w3(chain_id)
                                    try:
                                        tx = w3.eth.get_transaction(tx_hash)
                                        if tx:
                                            event = self._analyze_tx(chain_id, tx)
                                            if event:
                                                await self._emit(event)
                                    except Exception:
                                        pass
                        except asyncio.TimeoutError:
                            continue
                        except websockets.ConnectionClosed:
                            break

            except Exception as e:
                print(f'[MEMPOOL] WebSocket error ({chain_name}): {e}')
                await asyncio.sleep(5)  # Reconnect delay

    async def start(self, chain_ids: list = None, use_websocket: bool = False):
        """Start monitoring multiple chains concurrently."""
        if chain_ids is None:
            chain_ids = list(CHAINS.keys())

        self._running = True
        tasks = []

        for cid in chain_ids:
            if use_websocket:
                tasks.append(asyncio.create_task(
                    self.monitor_websocket(cid)
                ))
            else:
                tasks.append(asyncio.create_task(
                    self.poll_pending_pool(cid, interval=2.0)
                ))

        print(f'[MEMPOOL] Monitoring {len(tasks)} chains')
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self):
        self._running = False

    def get_recent_suspicious(self, min_priority: int = 2, limit: int = 20) -> list:
        """Get recent suspicious transactions filtered by priority."""
        filtered = [t for t in self._suspicious_txs if t.priority >= min_priority]
        # Trim
        if len(self._suspicious_txs) > self._max_suspicious:
            self._suspicious_txs = self._suspicious_txs[-self._max_suspicious:]
        return filtered[-limit:]

    def is_target_under_attack(self, chain_id: int, target_address: str,
                                window_seconds: int = 300) -> bool:
        """Check if a target contract has pending exploit transactions.

        Returns True if any high-priority tx targets this address in the
        last window_seconds.
        """
        now = time.time()
        cutoff = now - window_seconds
        target_lower = target_address.lower()

        for event in self._suspicious_txs:
            if (event.chain_id == chain_id and
                event.to_address.lower() == target_lower and
                event.timestamp > cutoff and
                event.priority >= 2):
                return True

        return False

    def get_oracle_manipulation_window(self, chain_id: int, token_address: str,
                                         window_seconds: int = 60) -> bool:
        """Check if a large DEX swap just happened that could create an
        oracle manipulation window for spot-price oracles."""
        now = time.time()
        cutoff = now - window_seconds

        for event in self._suspicious_txs:
            if (event.chain_id == chain_id and
                event.event_type == 'large_swap' and
                event.timestamp > cutoff and
                event.priority >= 2):
                return True

        return False
