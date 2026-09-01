"""T3-3 On-Chain State Prober.

Probes deployed contracts for vulnerabilities invisible to static analysis.
"""
import json
from typing import Optional
from web3 import Web3
from .config import CHAINS, ETH_PRICE_USD
from .db import Database


class OnChainProber:
    EIP1967_SLOTS = {
        'implementation': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
        'admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
        'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
    }
    VIEW_FUNCTIONS = [
        ('owner()', 'owner', 'address'), ('admin()', 'admin', 'address'),
        ('totalSupply()', 'totalSupply', 'uint256'), ('tvl()', 'tvl', 'uint256'),
        ('totalAssets()', 'totalAssets', 'uint256'), ('paused()', 'paused', 'bool'),
        ('proposalThreshold()', 'proposalThreshold', 'uint256'),
        ('quorumNumerator()', 'quorumNumerator', 'uint256'),
        ('votingDelay()', 'votingDelay', 'uint256'), ('votingPeriod()', 'votingPeriod', 'uint256'),
        ('timelock()', 'timelock', 'address'), ('guardian()', 'guardian', 'address'),
        ('pendingAdmin()', 'pendingAdmin', 'address'), ('pendingOwner()', 'pendingOwner', 'address'),
    ]

    def __init__(self, chain_id: int, db: Database = None):
        self.chain_id = chain_id
        self.chain = CHAINS.get(chain_id)
        self.db = db
        self.w3 = None
        self._connect()

    def _connect(self):
        if not self.chain:
            return
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.chain['rpc'], request_kwargs={'timeout': 15}))
        except Exception:
            self.w3 = None

    def is_connected(self):
        return self.w3 and self.w3.is_connected()

    def probe(self, address: str) -> dict:
        result = {
            'address': address, 'chain_id': self.chain_id,
            'chain_name': self.chain.get('name', 'unknown') if self.chain else 'unknown',
            'has_code': False, 'bytecode_size': 0,
            'native_balance': '0', 'native_balance_usd': '0',
            'is_proxy': False, 'proxy_type': None, 'implementation': None,
        }
        if not self.is_connected():
            result['error'] = 'Cannot connect'
            return result
        addr = Web3.to_checksum_address(address)
        try:
            code = self.w3.eth.get_code(addr)
            if not code or len(code) <= 2:
                result['error'] = 'No code (EOA)'
                return result
            result['has_code'] = True
            result['bytecode_size'] = len(code)
        except Exception as e:
            result['error'] = str(e)
            return result
        try:
            balance = self.w3.eth.get_balance(addr)
            eth_bal = self.w3.from_wei(balance, 'ether')
            result['native_balance'] = f'{eth_bal:.6f}'
            result['native_balance_usd'] = f'{eth_bal * ETH_PRICE_USD:.2f}'
        except Exception:
            pass
        result.update(self._detect_proxy(addr))
        result['view_data'] = self._probe_views(addr)
        result['callability'] = self._test_calls(addr)
        vd = result.get('view_data', {})
        if vd.get('proposalThreshold') is not None:
            result['governance'] = self._probe_gov(addr, vd)
        return result

    def _detect_proxy(self, addr):
        result = {'is_proxy': False, 'proxy_type': None, 'implementation': None}
        for slot_name, slot in self.EIP1967_SLOTS.items():
            try:
                data = self.w3.eth.get_storage_at(addr, slot)
                if data != bytes(32):
                    impl = '0x' + data[12:].hex()
                    result['is_proxy'] = True
                    if slot_name == 'implementation':
                        result['proxy_type'] = 'EIP-1967'
                        result['implementation'] = impl
                    elif slot_name == 'admin':
                        result['proxy_admin'] = impl
            except Exception:
                pass
        return result

    def _probe_views(self, addr):
        data = {}
        for sig, name, dtype in self.VIEW_FUNCTIONS:
            try:
                selector = Web3.keccak(text=sig)[:4]
                result = self.w3.eth.call({'to': addr, 'data': selector})
                if result and result != bytes(32):
                    if dtype == 'address' and len(result) == 32:
                        val = Web3.to_checksum_address('0x' + result[12:].hex())
                        if int(val, 16) > 0:
                            data[name] = val
                    elif dtype == 'uint256':
                        val = int.from_bytes(result, 'big')
                        if val > 0:
                            data[name] = str(val)
                    elif dtype == 'bool':
                        data[name] = result[-1] == 1
            except Exception:
                pass
        return data

    def _test_calls(self, addr):
        calls = {}
        for sig, name in [('initialize(address)', 'initialize'), ('withdraw()', 'withdraw')]:
            try:
                selector = Web3.keccak(text=sig)[:4]
                gas = self.w3.eth.estimate_gas({'from': '0x' + '00' * 20, 'to': addr, 'data': selector})
                calls[name] = {'callable': True, 'gas': gas}
            except Exception as e:
                calls[name] = {'callable': False, 'reason': str(e)[:200]}
        return calls

    def _probe_gov(self, addr, vd):
        gov = {}
        pt = vd.get('proposalThreshold', '')
        if pt:
            try:
                threshold = int(pt)
                gov['proposal_threshold'] = threshold
                gov['zero_threshold'] = threshold == 0
            except (ValueError, TypeError):
                pass
        qn = vd.get('quorumNumerator', '')
        if qn:
            try:
                gov['quorum_numerator'] = int(qn)
                gov['low_quorum'] = int(qn) < 4
            except (ValueError, TypeError):
                pass
        for role in ['owner', 'admin', 'guardian']:
            addr_val = vd.get(role, '')
            if addr_val:
                try:
                    code = self.w3.eth.get_code(Web3.to_checksum_address(addr_val))
                    gov[f'{role}_is_eoa'] = len(code) <= 2
                except Exception:
                    pass
        return gov
