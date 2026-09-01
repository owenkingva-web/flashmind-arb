"""P2 Real-Time Proxy Upgrade Event Monitor.

Monitors Upgraded() and AdminChanged() events across all chains.
When a protocol upgrades its implementation, the new code may contain bugs.
This is the HIGHEST VALUE monitoring channel for DeFi vulnerability hunting.
"""
from typing import Optional

import requests
from web3 import Web3

from .config import CHAINS
from .db import Database
from .fetcher import SourceFetcher
from .analyzer import VulnerabilityAnalyzer, Finding
from .alerts import AlertManager


UPGRADED_TOPIC = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b'
ADMIN_CHANGED_TOPIC = '0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f'
DEBILLAMA_HACKS_URL = 'https://api.llama.fi/v2/hacks'
BLOCK_RANGES = {1: 500, 42161: 10000, 8453: 2000, 56: 3000}


class UpgradeMonitor:
    """Real-time proxy upgrade event monitor across all chains."""

    def __init__(self, db: Database):
        self.db = db
        self.fetcher = SourceFetcher(db)
        self.analyzer = VulnerabilityAnalyzer(db)
        self.alerts = AlertManager()
        self._w3_cache: dict[int, Web3] = {}
        self._last_block: dict[int, int] = {}
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'VulnHunter/3.0'})
        self._recent_hacks: list[dict] = []
        self._init_start_blocks()

    def _init_start_blocks(self):
        for chain_id in CHAINS:
            try:
                w3 = self._get_w3(chain_id)
                if w3 and w3.is_connected():
                    self._last_block[chain_id] = w3.eth.block_number - BLOCK_RANGES.get(chain_id, 500)
            except Exception:
                self._last_block[chain_id] = 0

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

    def _fetch_recent_hacks(self) -> list[dict]:
        """Fetch recent hacks from DeFiLlama for same-category matching."""
        try:
            r = self._session.get(DEBILLAMA_HACKS_URL, timeout=15)
            if r.status_code == 200:
                hacks = r.json()
                self._recent_hacks = hacks[:50] if isinstance(hacks, list) else []
        except Exception:
            pass
        return self._recent_hacks

    def _find_similar_hacks(self, category: str) -> list[str]:
        """Find hacks in the same category for context."""
        if not self._recent_hacks:
            self._fetch_recent_hacks()
        similar, cat_lower = [], category.lower()
        for hack in self._recent_hacks:
            amount = hack.get('loss', 0) or 0
            hack_cats = ' '.join([hack.get('category', ''), hack.get('chains', [])]).lower()
            if cat_lower.split()[0] in hack_cats or any(w in hack_cats for w in cat_lower.split() if len(w) > 3):
                similar.append(f'{hack["name"]} (${amount:,.0f})')
        return similar[:5]

    def scan_chain(self, chain_id: int) -> list:
        """Scan a single chain for upgrade events since last block."""
        w3 = self._get_w3(chain_id)
        if not w3:
            return []
        chain_name = CHAINS.get(chain_id, {}).get('name', str(chain_id))
        from_block = self._last_block.get(chain_id, 0)
        try:
            current = w3.eth.block_number
        except Exception:
            return []
        if from_block >= current:
            return []
        upgrade_events = self._get_logs(w3, from_block, current, [UPGRADED_TOPIC])
        admin_events = self._get_logs(w3, from_block, current, [ADMIN_CHANGED_TOPIC])
        self._last_block[chain_id] = current
        results = []
        for event in upgrade_events:
            r = self._process_upgrade_event(event, chain_id, chain_name)
            if r:
                results.append(r)
        for event in admin_events:
            r = self._process_admin_event(event, chain_id, chain_name)
            if r:
                results.append(r)
        if results:
            print(f'[UPGRADE-MON] {chain_name}: {len(upgrade_events)} upgrades, {len(admin_events)} admin changes')
        return results

    def _get_logs(self, w3, from_block, to_block, topics):
        """Fetch logs with proper pagination for large ranges."""
        all_logs, chunk_size, start = [], 2000, from_block
        while start <= to_block:
            end = min(start + chunk_size - 1, to_block)
            try:
                logs = w3.eth.get_logs({'fromBlock': start, 'toBlock': end, 'topics': [topics]})
                all_logs.extend(logs)
            except Exception as e:
                if 'range' in str(e).lower() and chunk_size > 200:
                    chunk_size //= 2
                    continue
                break
            start = end + 1
        return all_logs

    def _process_upgrade_event(self, event, chain_id, chain_name):
        """Process Upgraded event: fetch and analyze new implementation."""
        topics = event.get('topics', [])
        if len(topics) < 2:
            return None
        proxy_addr = event.get('address', '')
        new_impl = '0x' + topics[1][-20:].hex()
        block = event.get('blockNumber', 0)
        tx_hash = event.get('transactionHash', b'').hex() if event.get('transactionHash') else ''
        print(f'[UPGRADE-MON] Upgrade: {proxy_addr} -> {new_impl} on {chain_name} block={block}')
        source_data = self.fetcher.fetch_source(new_impl, chain_id)
        findings = self.analyzer.analyze_contract(new_impl, chain_id, source_data) if source_data else []
        high_sev = [f for f in findings if f.severity in ('CRITICAL', 'HIGH')]
        result = {
            'type': 'upgrade', 'proxy': proxy_addr, 'implementation': new_impl,
            'chain_id': chain_id, 'chain_name': chain_name, 'block': block, 'tx_hash': tx_hash,
            'findings': [f.to_dict() for f in findings],
            'total_findings': len(findings), 'high_severity_count': len(high_sev),
        }
        if high_sev:
            similar = self._find_similar_hacks(high_sev[0].category)
            ctx = f' | Similar: {similar}' if similar else ''
            msg = (f'[UPGRADE] {chain_name}: {proxy_addr} -> {new_impl}\n'
                   f'{len(high_sev)} HIGH/CRITICAL. Top: {high_sev[0].title} ({high_sev[0].confidence:.0%}){ctx}')
            self.alerts.send_alert('proxy_upgrade', high_sev[0].severity, msg,
                                   contract_address=proxy_addr, chain_id=chain_id)
        return result

    def _process_admin_event(self, event, chain_id, chain_name):
        """Process AdminChanged event."""
        topics = event.get('topics', [])
        if len(topics) < 2:
            return None
        new_admin = '0x' + topics[1][-20:].hex()
        print(f'[UPGRADE-MON] Admin changed: {event["address"]} -> {new_admin} on {chain_name}')
        return {
            'type': 'admin_change', 'proxy': event.get('address', ''),
            'new_admin': new_admin, 'chain_id': chain_id, 'chain_name': chain_name,
            'block': event.get('blockNumber', 0),
            'tx_hash': event.get('transactionHash', b'').hex() if event.get('transactionHash') else '',
            'findings': [], 'high_severity_count': 0,
        }

    def scan_all(self) -> dict:
        """Scan all chains for upgrade events. Returns results per chain."""
        self._fetch_recent_hacks()
        results, total = {}, 0
        for chain_id in CHAINS:
            try:
                chain_results = self.scan_chain(chain_id)
                results[chain_id] = chain_results
                total += sum(r.get('high_severity_count', 0) for r in chain_results)
            except Exception as e:
                print(f'[UPGRADE-MON] {CHAINS[chain_id]["name"]} error: {e}')
                results[chain_id] = []
        if total:
            print(f'[UPGRADE-MON] Total: {total} HIGH/CRITICAL across all chains')
        return results
