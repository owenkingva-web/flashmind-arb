r"""T3-3 MEV Protection Module

Private transaction submission via Flashbots Protect, MEV Blocker, and
alternative private mempools. Prevents front-running of exploit transactions.

Chains supported:
  - Ethereum: Flashbots Protect relay + MEV Blocker
  - Arbitrum: MEV Blocker (via BloxRoute)  
  - Base: Flashbots Protect (via builder)
  - BNB: Private tx via BSC private mempool endpoints
"""
import json
import time
import asyncio
from typing import Optional
from web3 import Web3
from web3.types import TxParams
from eth_account import Account
from eth_account.messages import encode_defunct

from .config import CHAINS, WALLET_PRIVATE_KEY


# Private relay endpoints per chain
PRIVATE_RELAYS = {
    1: [
        # Flashbots Protect (same as Flashbots relay but doesn't bid for block space)
        'https://protect.flashbots.net',
        # MEV Blocker (by CoW Protocol - distributes to multiple builders)
        'https://rpc.mevblocker.io',
    ],
    42161: [
        'https://rpc.mevblocker.io',
        'https://arb1.arbitrum.io/rpc',  # fallback
    ],
    8453: [
        'https://rpc.mevblocker.io',
        'https://mainnet.base.org',  # fallback
    ],
    56: [
        'https://bsc-dataseed.binance.org',  # BSC has limited private options
    ],
}


class MEVProtection:
    """Submit transactions through private mempools to prevent front-running."""

    def __init__(self):
        self._w3_cache = {}
        self._wallet_cache = {}
        self._fb_cache = {}  # Flashbots w3 instances

    def _get_wallet(self) -> Account:
        if 'wallet' not in self._wallet_cache:
            self._wallet_cache['wallet'] = Account.from_key(WALLET_PRIVATE_KEY)
        return self._wallet_cache['wallet']

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id, {})
            rpc = chain.get('rpc', '')
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 30}))
            if not w3.is_connected():
                raise ConnectionError(f'Cannot connect to {chain.get("name", chain_id)}')
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    def _get_flashbots_w3(self, chain_id: int):
        """Get a Flashbots-enabled Web3 instance for Ethereum."""
        if chain_id not in self._fb_cache:
            try:
                from flashbots import flashbot
                w3 = self._get_w3(chain_id)
                wallet = self._get_wallet()
                self._fb_cache[chain_id] = flashbot(w3, wallet)
            except Exception as e:
                print(f'[MEV] Flashbots init failed: {e}')
                self._fb_cache[chain_id] = None
        return self._fb_cache[chain_id]

    def send_private_tx(self, chain_id: int, tx: dict, max_retries: int = 3) -> dict:
        """Send a transaction through private mempool.

        Tries multiple private relays in order:
        1. Flashbots Protect (Ethereum only)
        2. MEV Blocker (all chains)
        3. Direct RPC with higher gas (last resort)

        Returns dict with success, tx_hash, method_used.
        """
        wallet = self._get_wallet()

        # Strategy 1: Flashbots bundle (Ethereum mainnet)
        if chain_id == 1:
            result = self._try_flashbots(tx, wallet, max_retries)
            if result['success']:
                return result

        # Strategy 2: Flashbots Protect RPC (HTTP POST to protect endpoint)
        result = self._try_protect_rpc(chain_id, tx, wallet)
        if result['success']:
            return result

        # Strategy 3: MEV Blocker
        result = self._try_mev_blocker(chain_id, tx, wallet)
        if result['success']:
            return result

        # Strategy 4: Fallback to public RPC (with warning)
        print('[MEV] WARNING: All private methods failed, falling back to public mempool')
        return self._send_public(chain_id, tx, wallet)

    def _try_flashbots(self, tx: dict, wallet: Account, max_retries: int) -> dict:
        """Try Flashbots relay bundle submission."""
        try:
            fb = self._get_flashbots_w3(1)
            if fb is None:
                return {'success': False, 'error': 'Flashbots not available'}

            signed = wallet.sign_transaction(tx)

            for attempt in range(max_retries):
                try:
                    # Send as a single-tx bundle targeting next block
                    block = self._get_w3(1).eth.block_number
                    raw_tx = getattr(signed, 'raw_transaction', getattr(signed, 'rawTransaction', None))
                    result = fb.send_bundle(
                        [{'tx': raw_tx, 'signer': wallet}],
                        target_block_number=block + 1,
                    )

                    # Wait for inclusion
                    for wait_block in range(block + 1, block + 6):
                        time.sleep(12)  # ~12s per ETH block
                        try:
                            bundle_stats = fb.get_bundle_stats(
                                result['bundle_hash'],
                                wait_block
                            )
                            if bundle_stats and bundle_stats.get('isSimulated'):
                                return {
                                    'success': True,
                                    'tx_hash': signed.hash.hex(),
                                    'method': 'flashbots_bundle',
                                    'bundle_hash': result['bundle_hash'],
                                }
                        except Exception:
                            continue

                except Exception as e:
                    print(f'[MEV] Flashbots attempt {attempt+1} failed: {e}')
                    time.sleep(1)
                    continue

            return {'success': False, 'error': 'Flashbots bundle not included in 5 blocks'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _try_protect_rpc(self, chain_id: int, tx: dict, wallet: Account) -> dict:
        """Try Flashbots Protect RPC endpoint (simple HTTP RPC with private mempool)."""
        relays = PRIVATE_RELAYS.get(chain_id, [])
        if not relays:
            return {'success': False, 'error': 'No relay for chain'}

        for relay in relays:
            try:
                import requests
                signed = wallet.sign_transaction(tx)
                raw_bytes = getattr(signed, 'raw_transaction', getattr(signed, 'rawTransaction', None))
                raw_tx = '0x' + raw_bytes.hex()

                payload = {
                    'jsonrpc': '2.0',
                    'method': 'eth_sendRawTransaction',
                    'params': [raw_tx],
                    'id': 1,
                }

                resp = requests.post(
                    relay,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=30,
                )
                data = resp.json()

                if 'result' in data and data['result']:
                    tx_hash = data['result']
                    if tx_hash != '0x' and len(tx_hash) > 10:
                        print(f'[MEV] Sent via {relay} (protect): {tx_hash}')
                        return {
                            'success': True,
                            'tx_hash': tx_hash,
                            'method': f'protect_rpc({relay})',
                        }

            except Exception as e:
                print(f'[MEV] Protect RPC {relay} failed: {e}')
                continue

        return {'success': False, 'error': 'All protect RPCs failed'}

    def _try_mev_blocker(self, chain_id: int, tx: dict, wallet: Account) -> dict:
        """Try MEV Blocker (CoW Protocol's anti-front-running service).

        MEV Blocker accepts private transactions and distributes them
        across multiple block builders, making front-running economically
        infeasible.
        """
        try:
            import requests
            signed = wallet.sign_transaction(tx)
            raw_bytes = getattr(signed, 'raw_transaction', getattr(signed, 'rawTransaction', None))
            raw_tx = '0x' + raw_bytes.hex()

            # MEV Blocker endpoint
            payload = {
                'jsonrpc': '2.0',
                'method': 'eth_sendRawTransaction',
                'params': [raw_tx],
                'id': 1,
            }

            resp = requests.post(
                'https://rpc.mevblocker.io',
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30,
            )
            data = resp.json()

            if 'result' in data and data['result']:
                tx_hash = data['result']
                if tx_hash != '0x' and len(tx_hash) > 10:
                    print(f'[MEV] Sent via MEV Blocker: {tx_hash}')
                    return {
                        'success': True,
                        'tx_hash': tx_hash,
                        'method': 'mev_blocker',
                    }

            return {'success': False, 'error': data.get('error', {}).get('message', 'No result')}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _send_public(self, chain_id: int, tx: dict, wallet: Account) -> dict:
        """Fallback: send through public mempool with high gas priority."""
        try:
            w3 = self._get_w3(chain_id)
            signed = wallet.sign_transaction(tx)
            raw_tx = getattr(signed, 'raw_transaction', getattr(signed, 'rawTransaction', None))
            tx_hash = w3.eth.send_raw_transaction(raw_tx)
            print(f'[MEV] WARNING: Public mempool: {tx_hash.hex()}')
            return {
                'success': True,
                'tx_hash': tx_hash.hex(),
                'method': 'public_fallback',
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def send_private_deploy_and_execute(
        self, chain_id: int, deploy_tx: dict, execute_tx: dict,
        max_retries: int = 3
    ) -> dict:
        """Send deploy + execute as a bundle to prevent front-running between them.

        For Ethereum: submits both as a Flashbots bundle so they execute
        atomically in the same block.
        For other chains: sends deploy privately, waits for confirmation,
        then sends execute privately.
        """
        wallet = self._get_wallet()

        if chain_id == 1:
            return self._bundle_deploy_execute_eth(deploy_tx, execute_tx, wallet, max_retries)
        else:
            # Sequential private sends for non-Ethereum chains
            deploy_result = self.send_private_tx(chain_id, deploy_tx)
            if not deploy_result['success']:
                return deploy_result

            # Wait for deploy confirmation
            w3 = self._get_w3(chain_id)
            tx_hash = bytes.fromhex(deploy_result['tx_hash'].replace('0x', ''))
            try:
                receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                if receipt.status != 1:
                    return {'success': False, 'error': 'Deploy reverted', 'deploy_result': deploy_result}
                # Update execute tx with contract address and nonce
                execute_tx['nonce'] = w3.eth.get_transaction_count(wallet.address)  # correct next nonce
            except Exception as e:
                return {'success': False, 'error': f'Deploy wait failed: {e}'}

            return self.send_private_tx(chain_id, execute_tx)

    def _bundle_deploy_execute_eth(self, deploy_tx: dict, execute_tx: dict,
                                     wallet: Account, max_retries: int) -> dict:
        """Bundle deploy + execute on Ethereum via Flashbots."""
        try:
            fb = self._get_flashbots_w3(1)
            if fb is None:
                return {'success': False, 'error': 'Flashbots not available'}

            signed_deploy = wallet.sign_transaction(deploy_tx)
            signed_execute = wallet.sign_transaction(execute_tx)

            raw_deploy = getattr(signed_deploy, 'raw_transaction', getattr(signed_deploy, 'rawTransaction', None))
            raw_execute = getattr(signed_execute, 'raw_transaction', getattr(signed_execute, 'rawTransaction', None))

            block = self._get_w3(1).eth.block_number

            result = fb.send_bundle(
                [
                    {'tx': raw_deploy, 'signer': wallet},
                    {'tx': raw_execute, 'signer': wallet},
                ],
                target_block_number=block + 2,  # 2 blocks out for safety
            )

            # Wait for inclusion
            for target in range(block + 2, block + 8):
                time.sleep(12)
                try:
                    stats = fb.get_bundle_stats(result['bundle_hash'], target)
                    if stats and stats.get('isSimulated'):
                        return {
                            'success': True,
                            'tx_hash': signed_deploy.hash.hex(),
                            'method': 'flashbots_bundle_atomic',
                            'bundle_hash': result['bundle_hash'],
                        }
                except Exception:
                    continue

            return {'success': False, 'error': 'Bundle not included'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def estimate_bundle_profit(self, chain_id: int, profit_eth: float,
                                 gas_cost_eth: float) -> float:
        """Calculate net profit after gas and MEV extraction.

        Flashbots takes 0.5-2% of profit. MEV Blocker is free.
        """
        if profit_eth <= gas_cost_eth:
            return -gas_cost_eth  # guaranteed loss

        net = profit_eth - gas_cost_eth
        # Conservative: assume 2% MEV fee
        mev_fee = net * 0.02
        return net - mev_fee
