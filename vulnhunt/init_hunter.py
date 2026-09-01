"""P2 Uninitialized Proxy Hunter.

Finds proxies where initialize() was never called (OpenZeppelin Initializable pattern).
If _initialized slot 0 == 0, anyone can call initialize() to take ownership.
Historical: Parity Wallet $30M, Cover Protocol $4.4M (similar re-init)."""
from typing import Optional

from web3 import Web3

from .config import CHAINS
from .db import Database
from .alerts import AlertManager
from .poc_generator import PoCGenerator


EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
INIT_SLOT = '0x0000000000000000000000000000000000000000000000000000000000000000'
DISCOVERY_CHAINS = [42161, 8453]
NEW_PROXY_BLOCK_RANGE = 1000


class InitHunter:
    """Hunts for uninitialized proxy contracts across chains."""

    def __init__(self, db: Database):
        self.db = db
        self.alerts = AlertManager()
        self.poc_gen = PoCGenerator()
        self._w3_cache: dict[int, Web3] = {}

    def _get_w3(self, chain_id: int) -> Optional[Web3]:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id)
            if not chain:
                return None
            try:
                w3 = Web3(Web3.HTTPProvider(chain['rpc'], request_kwargs={'timeout': 15}))
                if w3.is_connected():
                    self._w3_cache[chain_id] = w3
                else:
                    return None
            except Exception:
                return None
        return self._w3_cache[chain_id]

    def _check_eip1967_impl(self, w3: Web3, address: str) -> Optional[str]:
        """Check EIP-1967 implementation slot, return impl address or None."""
        try:
            data = w3.eth.get_storage_at(Web3.to_checksum_address(address), EIP1967_IMPL_SLOT)
            if data == b'\x00' * 32:
                return None
            impl = '0x' + data[12:].hex()
            return impl if int(impl, 16) > 0 else None
        except Exception:
            return None

    def scan_known_proxies(self) -> list:
        """Scan all DB-known proxies for uninitialized state."""
        proxies = self.db.get_known_proxies()
        if not proxies:
            print('[INIT-HUNTER] No known proxies in DB')
            return []
        print(f'[INIT-HUNTER] Scanning {len(proxies)} known proxies...')
        vulnerable = []
        seen = set()
        for proxy in proxies:
            addr, chain_id = proxy.get('address', ''), proxy.get('chain_id', 0)
            key = f"{addr}:{chain_id}"
            if key in seen:
                continue
            seen.add(key)
            try:
                result = self.check_proxy(addr, chain_id)
                if result.get('vulnerable'):
                    vulnerable.append(result)
            except Exception as e:
                print(f'[INIT-HUNTER] Error checking {addr}: {e}')
        print(f'[INIT-HUNTER] Found {len(vulnerable)} uninitialized proxies')
        return vulnerable

    def scan_new_proxies(self, chain_id: int) -> list:
        """Discover new proxies in recent blocks and check initialization."""
        if chain_id not in DISCOVERY_CHAINS:
            return []
        w3 = self._get_w3(chain_id)
        if not w3:
            return []
        chain_name = CHAINS.get(chain_id, {}).get('name', str(chain_id))
        try:
            current = w3.eth.block_number
            from_block = max(0, current - NEW_PROXY_BLOCK_RANGE)
        except Exception:
            return []
        vulnerable = []
        print(f'[INIT-HUNTER] Scanning blocks {from_block}-{current} on {chain_name}...')
        block_range = range(from_block, current + 1)
        step = max(1, len(block_range) // 50)
        for block_num in block_range[::step]:
            try:
                block = w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.get('transactions', []):
                    if tx.get('to') is not None:
                        continue
                    receipt = w3.eth.get_transaction_receipt(tx.hash)
                    for log_entry in receipt.get('logs', []):
                        contract_addr = log_entry.get('address', '')
                        if not contract_addr:
                            continue
                        try:
                            if self._check_eip1967_impl(w3, contract_addr):
                                result = self.check_proxy(contract_addr, chain_id)
                                if result.get('vulnerable'):
                                    vulnerable.append(result)
                        except Exception:
                            continue
            except Exception:
                continue
        print(f'[INIT-HUNTER] {chain_name}: {len(vulnerable)} vulnerable new proxies')
        return vulnerable

    def check_proxy(self, address: str, chain_id: int) -> dict:
        """Check if a specific proxy is uninitialized."""
        w3 = self._get_w3(chain_id)
        if not w3:
            return {'vulnerable': False, 'error': 'no_connection'}
        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', str(chain_id))
        addr_cs = Web3.to_checksum_address(address)
        result = {
            'address': address, 'chain_id': chain_id, 'chain_name': chain_name,
            'vulnerable': False, 'implementation': None, 'initialized': None, 'finding': None,
        }
        try:
            code = w3.eth.get_code(addr_cs)
            if not code or len(code) <= 2:
                return result
        except Exception:
            return result
        impl = self._check_eip1967_impl(w3, address)
        if not impl:
            return result
        result['implementation'] = impl
        try:
            impl_code = w3.eth.get_code(Web3.to_checksum_address(impl))
            if not impl_code or len(impl_code) <= 2:
                result['error'] = 'implementation_no_code'
                return result
        except Exception:
            return result
        try:
            slot_data = w3.eth.get_storage_at(addr_cs, INIT_SLOT)
            initialized_val = int.from_bytes(slot_data, 'big')
            result['initialized'] = initialized_val
        except Exception:
            return result
        # _initialized == 0: NOT initialized (OpenZeppelin Initializable pattern)
        # _initialized == 1: initialized, 255: initializing (reentrant guard)
        if initialized_val == 0:
            print(f'[INIT-HUNTER] VULNERABLE: {address} on {chain_name} - _initialized == 0')
            finding = {
                'vuln_id': 'INIT-HUNT-001', 'category': 'Initialization',
                'severity': 'CRITICAL', 'confidence': 0.95, 'zero_capital': True,
                'title': f'Uninitialized proxy: {address[:10]}... on {chain_name}',
                'description': (f'Proxy {address} on {chain_name}: _initialized == 0. Impl: {impl}. '
                                f'Anyone can call initialize() to take ownership. Parity $30M, Cover $4.4M.'),
                'location': f'{address}:initialize()',
            }
            result['vulnerable'] = True
            result['finding'] = finding
            self._save_finding(address, chain_id, finding, impl)
            self.alerts.send_alert(
                'uninitialized_proxy', 'CRITICAL',
                f'⚠️ UNINITIALIZED PROXY: {address} on {chain_name} | impl: {impl}',
                contract_address=address, chain_id=chain_id)
            try:
                poc = self.poc_gen.generate_poc(finding, chain_id, address)
                if poc:
                    result['poc'] = poc
                    print(f'[INIT-HUNTER] PoC generated for {address[:10]}...')
            except Exception as e:
                print(f'[INIT-HUNTER] PoC gen failed: {e}')
        return result

    def _save_finding(self, address: str, chain_id: int, finding: dict, impl: str):
        """Persist finding to DB: contract, scan, finding."""
        contract_id = self.db.upsert_contract(address=address, chain_id=chain_id,
                                               is_proxy=True, implementation=impl)
        if not contract_id:
            return
        scan_id = self.db.create_scan(contract_id, scan_type='init_hunt')
        if not scan_id:
            return
        self.db.add_finding(
            scan_id=scan_id, vuln_id=finding['vuln_id'], category=finding['category'],
            severity=finding['severity'], title=finding['title'], description=finding['description'],
            location=finding['location'], confidence=finding['confidence'],
            zero_capital=finding['zero_capital'], raw_data={'impl': impl, 'source': 'init_hunter'})
