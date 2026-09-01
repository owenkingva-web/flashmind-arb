r"""T3-3 Liquidation Hunter

Scans lending protocols (Aave V3, Compound V3, Spark, Radiant) for
undercollateralized positions with healthFactor < 1.0.
Focuses on Aave V3 getUserAccountData for known/recent borrowers.
"""
import asyncio
import time
from datetime import datetime, timezone
from web3 import Web3

from .config import CHAINS, ETH_PRICE_USD
from .db import Database


# Lending pool addresses per chain
AAVE_V3_POOLS = {
    1: '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2',
    42161: '0x794a61358D6845594F94dc1DB02A252b5b4814aD',
    8453: '0xA238Dd80C259a72e81d7e4664a9801593F98d1c5',
}
COMPOUND_V3 = {1: '0xc3d688B66703497DAa19211EEdff47f25384cdc3'}
SPARK_POOLS = {1: '0x2442a9816C8aBC94470F6A2E6D5336DaB2F094a6'}
RADIANT_POOLS = {42161: '0xd50Cf00b6e600571b79764d28e3bbdd1e0E5c923'}

GET_USER_DATA_ABI = '''[
    {"inputs":[{"name":"user","type":"address"}],"name":"getUserAccountData",
     "outputs":[
        {"name":"totalCollateralBase","type":"uint256"},
        {"name":"totalDebtBase","type":"uint256"},
        {"name":"availableBorrowsBase","type":"uint256"},
        {"name":"currentLiquidationThreshold","type":"uint256"},
        {"name":"ltv","type":"uint256"},
        {"name":"healthFactor","type":"uint256"}],
     "stateMutability":"view","type":"function"}]'''

BORROW_SIG = '0x445cc7189b699aba312bd54ce4e386e25919e7992981f28a29855412132fce9c'  # Borrow(address,address,address,uint256,uint256,uint256,uint256)
SUPPLY_SIG = '0xe751baae971614714a5055ecbc0892f68c0e2d70c56550cb65a76bc840fa5f6e'  # Supply(address,address,address,uint256,uint256)


class LiquidationHunter:
    """Scans lending protocols for liquidatable positions."""

    def __init__(self, db: Database):
        self.db = db
        self._w3_cache: dict[int, Web3] = {}
        self._contract_cache: dict = {}
        self._running = False
        self._borrowers: dict[int, set] = {c: set() for c in CHAINS}

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            rpc = CHAINS.get(chain_id, {}).get('rpc', '')
            self._w3_cache[chain_id] = Web3(
                Web3.HTTPProvider(rpc, request_kwargs={'timeout': 15})
            )
        return self._w3_cache[chain_id]

    def _get_contract(self, chain_id: int, addr: str):
        key = f"{chain_id}:{addr.lower()}"
        if key not in self._contract_cache:
            w3 = self._get_w3(chain_id)
            self._contract_cache[key] = w3.eth.contract(
                address=Web3.to_checksum_address(addr), abi=GET_USER_DATA_ABI)
        return self._contract_cache[key]

    def _all_pools(self) -> list:
        pools = []
        for c, a in AAVE_V3_POOLS.items():
            pools.append((c, a, 'aave_v3'))
        for c, a in COMPOUND_V3.items():
            pools.append((c, a, 'compound_v3'))
        for c, a in SPARK_POOLS.items():
            pools.append((c, a, 'spark'))
        for c, a in RADIANT_POOLS.items():
            pools.append((c, a, 'radiant'))
        return pools

    def check_health(self, chain_id: int, pool_address: str,
                     user: str) -> dict:
        """Call getUserAccountData for a user. Returns health data dict."""
        try:
            contract = self._get_contract(chain_id, pool_address)
            r = contract.functions.getUserAccountData(
                Web3.to_checksum_address(user)).call()
            hf = r[5] / 1e18 if r[5] != 0 else float('inf')
            return {
                'chain_id': chain_id, 'pool': pool_address, 'user': user,
                'total_collateral_usd': r[0] / 1e8, 'total_debt_usd': r[1] / 1e8,
                'liquidation_threshold': r[3] / 1e4, 'ltv': r[4] / 1e4,
                'health_factor': hf, 'liquidatable': hf < 1.0,
            }
        except Exception as e:
            return {'error': str(e), 'user': user}

    def scan_protocol(self, chain_id: int, pool_address: str) -> list:
        """Check health of known borrowers, return liquidatable positions."""
        borrowers = self._borrowers.get(chain_id, set())
        if not borrowers:
            return []
        liquidatable = []
        for user in list(borrowers):
            try:
                data = self.check_health(chain_id, pool_address, user)
                if data.get('liquidatable'):
                    data['timestamp'] = datetime.now(timezone.utc).isoformat()
                    liquidatable.append(data)
                    print(f'[LIQ] {user[:10]}... HF={data["health_factor"]:.4f} '
                          f'debt=${data["total_debt_usd"]:.0f}')
            except Exception as e:
                print(f'[LIQ] Error checking {user}: {e}')
        for pos in liquidatable:
            self.db.log_execution(
                contract_address=pool_address, chain_id=chain_id,
                action='liquidation_detected', metadata=pos)
        return liquidatable

    def _discover_borrowers(self, chain_id: int, pool_addr: str) -> int:
        """Scan recent Borrow events to find active borrowers."""
        try:
            w3 = self._get_w3(chain_id)
            block = w3.eth.block_number
            from_block = max(0, block - 500)
            pool = Web3.to_checksum_address(pool_addr)
            new = 0
            for sig in [BORROW_SIG, SUPPLY_SIG]:
                try:
                    logs = w3.eth.get_logs({
                        'fromBlock': from_block, 'toBlock': block,
                        'address': pool, 'topics': [sig]})
                    for log in logs:
                        if len(log.topics) > 1:
                            user = '0x' + log.topics[1][-20:].hex()
                            if user not in self._borrowers[chain_id]:
                                self._borrowers[chain_id].add(user)
                                new += 1
                except Exception:
                    pass
            if new:
                print(f'[LIQ] Found {new} new borrowers on chain {chain_id}')
            return new
        except Exception as e:
            print(f'[LIQ] Discovery error: {e}')
            return 0

    def scan_all_chains(self) -> dict:
        """Scan all lending pools across all chains.

        Returns {chain_id: [liquidatable_positions]}.
        """
        results = {}
        for cid, addr, proto in self._all_pools():
            name = CHAINS.get(cid, {}).get('name', str(cid))
            try:
                self._discover_borrowers(cid, addr)
                liqs = self.scan_protocol(cid, addr)
                if liqs:
                    results.setdefault(cid, []).extend(liqs)
            except Exception as e:
                print(f'[LIQ] Error {proto}@{name}: {e}')
        total = sum(len(v) for v in results.values())
        print(f'[LIQ] {total} liquidatable positions across {len(results)} chains')
        return results

    async def run(self, interval: float = 30.0):
        """Continuous liquidation scanning loop."""
        self._running = True
        print(f'[LIQ] Starting (every {interval}s)')
        while self._running:
            try:
                self.scan_all_chains()
            except Exception as e:
                print(f'[LIQ] Scan error: {e}')
            await asyncio.sleep(interval)

    def stop(self):
        self._running = False
