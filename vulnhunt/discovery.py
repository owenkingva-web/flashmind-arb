"""T3-3 Multi-Channel Discovery Engine v3.1

Discovers DeFi targets from 12+ channels:
1. DeFiLlama protocol listings (ALL, not just new)
2. DeFiLlama protocol changes (TVL spikes, new chain additions)
3. Block explorer new verified contracts
4. Block explorer ALL DeFi-like verified contracts (re-scan pool)
5. Uniswap V2/V3 factory new pool events
6. Camelot, Aerodrome, PancakeSwap V2/V3 factory pools
7. New proxy deployments (EIP-1967 scanning)
8. Proxy UPGRADE events (implementation changes = re-scan)
9. Governance proposal monitoring
10. New token deployments (suspicious patterns)
11. Contract upgrade event monitoring (Upgraded, AdminChanged)
12. DeFiLlama hacks/bridge additions feed
"""
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import requests
from web3 import Web3
from .config import CHAINS, KNOWN_SAFE_PROTOCOLS, DEFAULT_SCAN
from .db import Database


@dataclass
class DiscoveredTarget:
    source: str
    address: str
    chain_id: int
    name: str = ""
    slug: str = ""
    category: str = ""
    tvl: float = 0
    protocol_id: int = 0
    metadata: dict = field(default_factory=dict)
    priority: int = 0


# DeFiLlama chain name -> our chain_id mapping
CHAIN_NAME_TO_ID = {
    'ethereum': 1, 'arbitrum': 42161, 'base': 8453,
    'bsc': 56, 'bnb': 56, 'binance': 56,
}


class DiscoveryEngine:
    def __init__(self, db: Database):
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnHunter/2.0"})
        self._rate_limit = DEFAULT_SCAN["etherscan_rate_limit"]
        self._defillama_chain_cache: dict = {}  # slug -> {chain_name: address}

    def _get_defillama_chain_addresses(self, slug: str, budget_remaining: int = 0) -> dict:
        """Fetch per-chain addresses from DeFiLlama /protocols/{slug}.
        Returns {chain_name: address} e.g. {'Arbitrum': '0x123...', 'Base': '0x456...'}.
        Uses in-memory cache to avoid redundant API calls.
        budget_remaining: stop making new API calls when this hits 0.
        """
        if slug in self._defillama_chain_cache:
            return self._defillama_chain_cache[slug]
        if budget_remaining <= 0:
            self._defillama_chain_cache[slug] = {}
            return {}
        try:
            r = self.session.get(
                f"https://api.llama.fi/protocols/{slug}", timeout=5
            )
            if r.status_code != 200:
                self._defillama_chain_cache[slug] = {}
                return {}
            data = r.json()
            chain_addrs = {}
            single_addr = data.get('address', '')
            methodology = data.get('methodology', '')
            all_addrs = re.findall(r'0x[a-fA-F0-9]{40}', methodology)
            chain_tvls = data.get('currentChainTvls', {})
            if not chain_tvls:
                self._defillama_chain_cache[slug] = {}
                return {}
            active_chains = list(chain_tvls.keys())
            if all_addrs and len(all_addrs) >= len(active_chains):
                for i, chain_name in enumerate(active_chains):
                    if i < len(all_addrs):
                        chain_addrs[chain_name] = all_addrs[i]
            elif single_addr and len(single_addr) == 42:
                top_chain = max(chain_tvls, key=chain_tvls.get) if chain_tvls else None
                if top_chain:
                    chain_addrs[top_chain] = single_addr
            self._defillama_chain_cache[slug] = chain_addrs
            return chain_addrs
        except Exception:
            self._defillama_chain_cache[slug] = {}
            return {}

    def _chain_name_to_id(self, chain_name: str) -> int:
        """Map DeFiLlama chain name to our chain_id."""
        return CHAIN_NAME_TO_ID.get(chain_name.lower())

    def discover_defillama(self, min_tvl=0, max_tvl=5_000_000, days_old=90, chains=None):
        print("[DISCOVERY] Polling DeFiLlama (per-chain addresses)...")
        try:
            r = self.session.get("https://api.llama.fi/protocols", timeout=30)
            r.raise_for_status()
            all_protos = r.json()
        except Exception as e:
            print(f"[DISCOVERY] DeFiLlama failed: {e}")
            return []

        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - (days_old * 86400)
        targets = []
        per_chain_budget = 20  # Max 20 individual API calls per cycle
        for p in all_protos:
            slug = p.get("slug", "")
            if slug in KNOWN_SAFE_PROTOCOLS:
                continue
            listed_ts = p.get("listedAt", 0)
            if listed_ts and listed_ts < cutoff:
                continue
            tvl = p.get("tvl", 0) or 0
            if tvl < min_tvl or tvl > max_tvl:
                continue
            proto_chains = p.get("chains", [])
            chain_ids = self._resolve_chain_ids(proto_chains, chains)
            if not chain_ids:
                continue
            # P0-4 FIX: Use per-chain addresses from DeFiLlama
            per_chain_addrs = self._get_defillama_chain_addresses(slug, per_chain_budget)
            per_chain_budget -= (0 if slug in self._defillama_chain_cache else 1)
            methodology = p.get("methodology", "")
            extra_addrs = re.findall(r"0x[a-fA-F0-9]{40}", methodology)
            protocol_id = self.db.upsert_protocol(
                slug=slug, name=p.get("name", "Unknown"),
                category=p.get("category", ""), tvl=tvl,
                chains=chain_ids, address=p.get("address", ""),
                url=p.get("url", ""),
                listed_at=datetime.fromtimestamp(listed_ts, tz=timezone.utc).isoformat() if listed_ts else "",
            )
            # Map per-chain addresses to targets
            if per_chain_addrs:
                for dl_chain_name, addr in per_chain_addrs.items():
                    cid = self._chain_name_to_id(dl_chain_name)
                    if not cid or (chains and cid not in chains):
                        continue
                    if addr.startswith("0x") and len(addr) == 42:
                        targets.append(DiscoveredTarget(
                            source="defillama_per_chain", address=addr, chain_id=cid,
                            name=p.get("name", ""), slug=slug,
                            category=p.get("category", ""), tvl=tvl,
                            protocol_id=protocol_id,
                            priority=int(min(tvl / 1000, 100)),
                        ))
            else:
                # Fallback: use methodology addresses (chain-agnostic, lower confidence)
                for addr in extra_addrs:
                    full = addr if addr.startswith("0x") else "0x" + addr
                    if len(full) == 42:
                        for cid in chain_ids:
                            targets.append(DiscoveredTarget(
                                source="defillama_methodology", address=full, chain_id=cid,
                                name=p.get("name", ""), slug=slug,
                                protocol_id=protocol_id, priority=int(min(tvl / 1000, 50)),
                            ))
        print(f"[DISCOVERY] DeFiLlama: {len(targets)} targets (per-chain)")
        return targets

    def discover_new_verified_contracts(self, chain_id: int, pages: int = 3):
        chain = CHAINS.get(chain_id)
        if not chain:
            return []
        targets = []
        api_key = chain.get("api_key", "")
        for page in range(1, pages + 1):
            params = {
                "chainid": chain_id,
                "module": "contract", "action": "listcontracts",
                "filter": "verified", "startpage": page, "endpage": page,
                "sort": "createdate", "order": "desc", "apikey": api_key,
            }
            try:
                r = self.session.get(chain["explorer_api"], params=params, timeout=15)
                if r.status_code != 200:
                    continue
                data = r.json()
                if data.get("status") != "1":
                    break
                contracts = data.get("result", [])
                if not contracts:
                    break
                for c in contracts:
                    addr = c.get("Address", "")
                    name = c.get("ContractName", "")
                    if not addr or len(addr) != 42:
                        continue
                    if self._is_defi_like(name):
                        existing = self.db.get_contract(addr, chain_id)
                        if existing and existing.get("is_verified"):
                            continue
                        targets.append(DiscoveredTarget(
                            source="new_verified", address=addr, chain_id=chain_id,
                            name=name, category="unknown_new", priority=30,
                            metadata={"contract_name": name},
                        ))
                time.sleep(self._rate_limit)
            except Exception as e:
                print(f"[DISCOVERY] Explorer page {page} failed: {e}")
                break
        print(f"[DISCOVERY] New verified on {chain['name']}: {len(targets)} DeFi-like")
        return targets

    # All DEX factories across chains for maximum pool coverage
    # topic0 = keccak256 of event signature (full 32 bytes)
    DEX_FACTORIES = {
        # Ethereum
        1: {
            'Uniswap V2': ('0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'Uniswap V3': ('0x1F98431c8aD98523631AE4a59f267346ea31F984', 'PoolCreated', '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'),
            'Sushi V2': ('0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
        },
        # Arbitrum
        42161: {
            'Uniswap V2': ('0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'Uniswap V3': ('0x1F98431c8aD98523631AE4a59f267346ea31F984', 'PoolCreated', '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'),
            'Sushi V2': ('0xc35DADB65012eC5796536bD9864eD8773aBc74C4', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'Camelot V2': ('0x6EcCab42245a261833E24A861cEA18396331b0b6', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'Camelot V3': ('0x1a3c9B1d2E05ea3a83E561C3E5e4B25A3FbeA96e', 'PoolCreated', '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'),
        },
        # Base
        8453: {
            'Uniswap V2': ('0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'Uniswap V3': ('0x33128a8fC17869897dcE68Ed026d694621f6FDfD', 'PoolCreated', '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'),
            'Aerodrome V2': ('0x420DD38197a6B8577c878EE9493bEA21C612E7f7', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
        },
        # BNB
        56: {
            'PancakeSwap V2': ('0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73', 'PairCreated', '0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9'),
            'PancakeSwap V3': ('0x0BFbCF9fa4f9C56B0F40a671Ad40E08004A97916', 'PoolCreated', '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118'),
        },
    }
    # EIP-1967 implementation slot
    EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    # Proxy upgrade event signatures (real keccak256 hashes)
    UPGRADED_SIG = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"  # Upgraded(address)
    ADMIN_CHANGED_SIG = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"  # AdminChanged(address,address)

    def discover_new_dex_pools(self, chain_id: int, blocks: int = None):
        """Scan ALL DEX factories on a chain for new pool creation events."""
        chain = CHAINS.get(chain_id)
        factories = self.DEX_FACTORIES.get(chain_id, {})
        if not chain or not factories:
            return []
        # Default block range per chain (smaller for public RPCs to avoid 413)
        if blocks is None:
            blocks = {1: 5000, 42161: 50000, 8453: 5000, 56: 10000}.get(chain_id, 5000)
        try:
            w3 = Web3(Web3.HTTPProvider(chain["rpc"], request_kwargs={"timeout": 15}))
            if not w3.is_connected():
                return []
        except Exception:
            return []
        latest = w3.eth.get_block_number()
        from_block = max(0, latest - blocks)
        targets = []
        for factory_name, (factory_addr, event_name, event_sig) in factories.items():
            try:
                logs = w3.eth.get_logs({
                    "fromBlock": from_block, "toBlock": latest,
                    "address": Web3.to_checksum_address(factory_addr),
                    "topics": [event_sig],
                })
                for log in logs:
                    # V2 PairCreated(address indexed token0, address indexed token1, address pair, uint256)
                    #   topics[1]=token0, topics[2]=token1, data=[pair(32B) + size(32B)]
                    # V3 PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool)
                    #   topics[1]=token0, topics[2]=token1, topics[3]=fee, data=[tickSpacing(32B) + pool(32B)]
                    token0 = "0x" + log["topics"][1].hex()[-40:]
                    token1 = "0x" + log["topics"][2].hex()[-40:]
                    # For V3, pool address is in data (last 20 bytes)
                    if event_name == 'PoolCreated' and len(log.get('data', '')) > 2:
                        try:
                            data_hex = log['data'].hex() if isinstance(log['data'], bytes) else log['data']
                            if len(data_hex) >= 40:
                                pool_addr = "0x" + data_hex[-40:]
                        except Exception:
                            pool_addr = ''
                    else:
                        # V2: pair address is first 20 bytes of data (left-padded to 32)
                        try:
                            data_hex = log['data'].hex() if isinstance(log['data'], bytes) else log['data']
                            if len(data_hex) >= 64:
                                pool_addr = "0x" + data_hex[24:64]  # bytes 12-31 of first slot
                        except Exception:
                            pool_addr = ''
                    targets.append(DiscoveredTarget(
                        source=f"new_{factory_name.lower().replace(' ', '_')}_pool",
                        address=pool_addr, chain_id=chain_id,
                        name=f"{factory_name} Pool", category="dex_pool",
                        priority=40,
                        metadata={
                            "factory": factory_name, "token0": token0,
                            "token1": token1, "block": log["blockNumber"],
                        },
                    ))
                if logs:
                    print(f"[DISCOVERY] {len(logs)} new {factory_name} pools on {chain['name']}")
            except Exception as e:
                print(f"[DISCOVERY] {factory_name} pool scan failed: {e}")
        return targets

    def discover_new_proxies(self, targets):
        proxy_targets = []
        seen = set()
        for t in targets:
            chain = CHAINS.get(t.chain_id)
            if not chain:
                continue
            try:
                w3 = Web3(Web3.HTTPProvider(chain["rpc"], request_kwargs={"timeout": 10}))
                if not w3.is_connected():
                    continue
                slot_data = w3.eth.get_storage_at(
                    Web3.to_checksum_address(t.address), self.EIP1967_IMPL_SLOT)
                if slot_data != bytes(32):
                    impl_addr = "0x" + slot_data[12:].hex()
                    if impl_addr == "0x" + "00" * 40:
                        proxy_targets.append(DiscoveredTarget(
                            source="uninitialized_proxy", address=t.address, chain_id=t.chain_id,
                            name=t.name or "Uninitialized Proxy", category="CRITICAL:uninitialized_proxy",
                            priority=100, metadata={"impl": impl_addr},
                        ))
                    elif impl_addr not in seen:
                        seen.add(impl_addr)
                        proxy_targets.append(DiscoveredTarget(
                            source="proxy_impl", address=impl_addr, chain_id=t.chain_id,
                            name=f"Proxy Impl of {t.name}", category="proxy_impl",
                            priority=20, metadata={"proxy_address": t.address},
                        ))
            except Exception:
                continue
        if proxy_targets:
            print(f"[DISCOVERY] {len(proxy_targets)} proxy targets")
        return proxy_targets

    def discover_governance_targets(self):
        targets = []
        try:
            r = self.session.get("https://api.llama.fi/protocols", timeout=30)
            r.raise_for_status()
            protos = r.json()
        except Exception:
            return targets
        gov_kw = ["governance", "dao", "treasury", "staking", "vote"]
        for p in protos:
            slug = p.get("slug", "")
            name = p.get("name", "")
            if slug in KNOWN_SAFE_PROTOCOLS:
                continue
            tvl = p.get("tvl", 0) or 0
            misc = json.dumps(p.get("misc", {})).lower()
            url = (p.get("url", "") or "").lower()
            has_gov = any(kw in misc or kw in url or kw in slug.lower() or kw in name.lower()
                         for kw in gov_kw)
            if has_gov and tvl > 10000:
                address = p.get("address", "")
                chain_ids = self._resolve_chain_ids(p.get("chains", []))
                for cid in chain_ids:
                    if address:
                        targets.append(DiscoveredTarget(
                            source="governance_monitor", address=address, chain_id=cid,
                            name=f"{name} (Governance)", slug=slug,
                            category="governance", tvl=tvl,
                            priority=int(min(tvl / 500, 80)),
                            metadata={"check_governance": True},
                        ))
        print(f"[DISCOVERY] Governance: {len(targets)} targets")
        return targets

    def discover_suspicious_tokens(self, chain_id: int, pages: int = 2):
        chain = CHAINS.get(chain_id)
        if not chain:
            return []
        targets = []
        api_key = chain.get("api_key", "")
        for page in range(1, pages + 1):
            params = {
                "chainid": chain_id,
                "module": "account", "action": "txlist",
                "address": "0x0000000000000000000000000000000000000000",
                "startblock": 0, "endblock": 99999999,
                "page": page, "offset": 50, "filterby": "create",
                "sort": "desc", "apikey": api_key,
            }
            try:
                r = self.session.get(chain["explorer_api"], params=params, timeout=15)
                if r.status_code != 200:
                    continue
                data = r.json()
                if data.get("status") != "1":
                    break
                txs = data.get("result", [])
                for tx in txs:
                    addr = tx.get("contractAddress", "")
                    if not addr or len(addr) != 42:
                        continue
                    existing = self.db.get_contract(addr, chain_id)
                    if existing:
                        continue
                    targets.append(DiscoveredTarget(
                        source="new_token", address=addr, chain_id=chain_id,
                        name=f"New Token {addr[:10]}...", category="new_token",
                        priority=15,
                        metadata={"creator": tx.get("from", ""), "block": tx.get("blockNumber", "")},
                    ))
                time.sleep(self._rate_limit)
            except Exception:
                break
        print(f"[DISCOVERY] New tokens on {chain['name']}: {len(targets)}")
        return targets

    def discover_defillama_changes(self, chains=None):
        """Channel 2: Re-scan ALL DeFiLlama protocols (not just new ones).
        Uses per-chain addresses from /protocols/{slug} endpoint.
        Targets get flagged for re-scan if TVL changed significantly, new chain added, etc.
        This expands the target surface from ~10 new/week to ~300+ total.
        """
        print("[DISCOVERY] Polling DeFiLlama ALL protocols (per-chain)...")
        try:
            r = self.session.get("https://api.llama.fi/protocols", timeout=30)
            r.raise_for_status()
            all_protos = r.json()
        except Exception as e:
            print(f"[DISCOVERY] DeFiLlama failed: {e}")
            return []

        targets = []
        for p in all_protos:
            slug = p.get("slug", "")
            if slug in KNOWN_SAFE_PROTOCOLS:
                continue
            tvl = p.get("tvl", 0) or 0
            proto_chains = p.get("chains", [])
            chain_ids = self._resolve_chain_ids(proto_chains, chains)
            if not chain_ids:
                continue

            # Check for changes since last scan
            existing_proto = self.db.get_protocol_by_slug(slug)
            changed = False
            change_reason = ''
            if existing_proto:
                old_tvl = existing_proto.get('tvl', 0)
                old_chains = json.loads(existing_proto.get('chains', '[]'))
                if tvl > 0 and old_tvl > 0 and tvl > old_tvl * 1.5:
                    changed = True
                    change_reason = f'tvl_spike_{old_tvl:.0f}_{tvl:.0f}'
                if tvl > 0 and old_tvl > 0 and tvl < old_tvl * 0.7:
                    changed = True
                    change_reason = f'tvl_crash_{old_tvl:.0f}_{tvl:.0f}'
                new_chains = set(chain_ids) - set(old_chains)
                if new_chains:
                    changed = True
                    change_reason = f'new_chain_{new_chains}'
            else:
                changed = True
                change_reason = 'new_protocol'

            # Update protocol in DB
            protocol_id = self.db.upsert_protocol(
                slug=slug, name=p.get("name", "Unknown"),
                category=p.get("category", ""), tvl=tvl,
                chains=chain_ids, address=p.get("address", ""),
                url=p.get("url", ""),
                listed_at=datetime.fromtimestamp(
                    p.get("listedAt", 0), tz=timezone.utc
                ).isoformat() if p.get("listedAt") else "",
            )

            if not changed:
                continue

            # P0-4 FIX: Use per-chain addresses instead of single address
            per_chain_budget_local = 30  # Budget for per-chain API calls
            per_chain_addrs = self._get_defillama_chain_addresses(slug, per_chain_budget_local)
            per_chain_budget_local -= (0 if slug in self._defillama_chain_cache else 1)
            if per_chain_addrs:
                for dl_chain_name, addr in per_chain_addrs.items():
                    cid = self._chain_name_to_id(dl_chain_name)
                    if not cid or (chains and cid not in chains):
                        continue
                    if addr.startswith("0x") and len(addr) == 42:
                        targets.append(DiscoveredTarget(
                            source=f"defillama_{change_reason}",
                            address=addr, chain_id=cid,
                            name=p.get("name", ""), slug=slug,
                            category=p.get("category", ""), tvl=tvl,
                            protocol_id=protocol_id,
                            priority=int(min(tvl / 500, 100)) + 30,
                        ))
            else:
                # Fallback: methodology addresses
                methodology = p.get("methodology", "")
                extra_addrs = re.findall(r"0x[a-fA-F0-9]{40}", methodology)
                for addr in extra_addrs:
                    full = addr if addr.startswith("0x") else "0x" + addr
                    if len(full) == 42:
                        for cid in chain_ids:
                            targets.append(DiscoveredTarget(
                                source=f"defillama_methodology_{change_reason}",
                                address=full, chain_id=cid,
                                name=p.get("name", ""), slug=slug,
                                protocol_id=protocol_id,
                                priority=int(min(tvl / 1000, 80)) + 20,
                            ))
        print(f"[DISCOVERY] DeFiLlama changes: {len(targets)} targets (per-chain)")
        return targets

    def discover_all_defi_verified(self, chain_id: int, pages: int = 5):
        """Channel 4: Scan ALL DeFi-like verified contracts on explorers, not just new ones.
        This pulls hundreds of contracts per chain per cycle.
        """
        chain = CHAINS.get(chain_id)
        if not chain:
            return []
        targets = []
        api_key = chain.get("api_key", "")
        for page in range(1, pages + 1):
            params = {
                "chainid": chain_id,
                "module": "contract", "action": "listcontracts",
                "startpage": page, "endpage": page,
                "sort": "createdate", "order": "desc", "apikey": api_key,
            }
            try:
                r = self.session.get(chain["explorer_api"], params=params, timeout=15)
                if r.status_code != 200:
                    continue
                data = r.json()
                if data.get("status") != "1":
                    break
                contracts = data.get("result", [])
                if not contracts:
                    break
                for c in contracts:
                    addr = c.get("Address", "")
                    name = c.get("ContractName", "")
                    if not addr or len(addr) != 42:
                        continue
                    if self._is_defi_like(name):
                        targets.append(DiscoveredTarget(
                            source="all_defi_verified", address=addr, chain_id=chain_id,
                            name=name, category="defi_contract",
                            priority=25,
                            metadata={"contract_name": name, "force_rescan": True},
                        ))
                time.sleep(self._rate_limit)
            except Exception as e:
                print(f"[DISCOVERY] All verified page {page} failed: {e}")
                break
        print(f"[DISCOVERY] All DeFi verified on {chain['name']}: {len(targets)} contracts")
        return targets

    def discover_proxy_upgrades(self, chain_ids: list, blocks: int = 10000):
        """Channel 8: Monitor for proxy UPGRADE events.
        When a proxy implementation changes, the new code needs re-scanning.
        This catches live protocol upgrades that may introduce bugs.
        """
        targets = []
        # Get all known proxy contracts from DB
        known_proxies = self.db.get_known_proxies()
        for proxy in known_proxies:
            chain_id = proxy['chain_id']
            chain = CHAINS.get(chain_id)
            if not chain:
                continue
            try:
                w3 = Web3(Web3.HTTPProvider(chain["rpc"], request_kwargs={"timeout": 10}))
                if not w3.is_connected():
                    continue
                current_impl = w3.eth.get_storage_at(
                    Web3.to_checksum_address(proxy['address']),
                    self.EIP1967_IMPL_SLOT,
                )
                current_impl_addr = "0x" + current_impl[-20:].hex()
                old_impl = proxy.get('implementation', '').lower()
                if current_impl_addr.lower() != old_impl:
                    # Implementation changed! Priority target
                    print(f"[DISCOVERY] UPGRADE DETECTED: {proxy['address'][:12]}... -> {current_impl_addr[:12]}...")
                    targets.append(DiscoveredTarget(
                        source="proxy_upgrade", address=current_impl_addr, chain_id=chain_id,
                        name=f"New impl of {proxy.get('contract_name', 'proxy')}",
                        category="upgraded_proxy_impl",
                        priority=95,
                        metadata={
                            "proxy_address": proxy['address'],
                            "old_implementation": old_impl,
                            "new_implementation": current_impl_addr,
                            "force_rescan": True,
                        },
                    ))
                    # Also re-scan the proxy itself
                    targets.append(DiscoveredTarget(
                        source="proxy_upgrade_self", address=proxy['address'], chain_id=chain_id,
                        name=proxy.get('contract_name', 'proxy'),
                        category="upgraded_proxy",
                        priority=90,
                        metadata={"force_rescan": True},
                    ))
            except Exception:
                continue
        if targets:
            print(f"[DISCOVERY] Proxy upgrades: {len(targets)} targets")
        return targets

    def discover_defillama_recent_hacks(self):
        """Channel 12: Check DeFiLlama's hacks feed for recently exploited protocols.
        If a protocol was hacked, check for similar patterns in other protocols.
        """
        targets = []
        try:
            r = self.session.get("https://api.llama.fi/hacks", timeout=15)
            r.raise_for_status()
            hacks = r.json()
        except Exception:
            return targets
        # Get hacks from last 30 days
        cutoff = time.time() - (30 * 86400)
        recent_hacks = [h for h in hacks if h.get('date', 0) > cutoff]
        if not recent_hacks:
            return targets
        # Extract unique protocols that were hacked
        hacked_slugs = set()
        for h in recent_hacks:
            hacked_slugs.add(h.get('name', '').lower())
        # Now find SIMILAR protocols (same category) that might share the same vulnerability pattern
        try:
            r = self.session.get("https://api.llama.fi/protocols", timeout=30)
            r.raise_for_status()
            protos = r.json()
        except Exception:
            return targets
        for p in protos:
            slug = p.get("slug", "")
            if slug in KNOWN_SAFE_PROTOCOLS or slug in hacked_slugs:
                continue
            name = p.get("name", "")
            category = p.get("category", "")
            # If this protocol is in the same category as a hacked one, scan it
            for h in recent_hacks:
                hacked_cat = h.get('category', '')
                if hacked_cat and hacked_cat.lower() == category.lower():
                    address = p.get("address", "")
                    if address and len(address) == 42:
                        chain_ids = self._resolve_chain_ids(p.get("chains", []))
                        for cid in chain_ids:
                            targets.append(DiscoveredTarget(
                                source="same_category_as_hacked",
                                address=address, chain_id=cid,
                                name=f"{name} (same cat as {h.get('name', 'hacked')})",
                                slug=slug, category=category,
                                tvl=p.get("tvl", 0),
                                priority=75,
                                metadata={
                                    "hack_reference": h.get('name', ''),
                                    "hacked_amount": h.get('amount', 0),
                                    "force_rescan": True,
                                },
                            ))
                    break
        if targets:
            print(f"[DISCOVERY] Same-category-as-hacked: {len(targets)} targets")
        return targets

    def run_full_discovery(self, chain_ids=None, min_tvl=0, max_tvl=5_000_000, days_old=90):
        """v3.1: Expanded discovery with 12 channels.
        Targets ~200-500+ contracts per cycle instead of ~10-30.
        """
        all_targets = []
        if chain_ids is None:
            chain_ids = [42161, 8453, 56, 1]
        # Channel 1: DeFiLlama NEW protocols (filtered by days_old)
        all_targets.extend(self.discover_defillama(min_tvl=min_tvl, max_tvl=max_tvl, days_old=days_old, chains=chain_ids))
        # Channel 2: DeFiLlama ALL protocols (change detection, re-scan)
        all_targets.extend(self.discover_defillama_changes(chains=chain_ids))
        # Channel 3: New verified DeFi contracts
        for cid in chain_ids:
            all_targets.extend(self.discover_new_verified_contracts(cid, pages=3))
        # Channel 4: ALL DeFi-like verified contracts (expanded surface)
        for cid in chain_ids:
            all_targets.extend(self.discover_all_defi_verified(cid, pages=5))
        # Channel 5: DEX pools from ALL factories
        for cid in chain_ids:
            all_targets.extend(self.discover_new_dex_pools(cid, blocks=10000))
        # Channel 6: Proxy scanning
        proxy_targets = self.discover_new_proxies(all_targets[:100])
        all_targets.extend(proxy_targets)
        # Channel 7: Proxy UPGRADE detection (re-scan changed impls)
        all_targets.extend(self.discover_proxy_upgrades(chain_ids))
        # Channel 8: Governance
        all_targets.extend(self.discover_governance_targets())
        # Channel 9: New tokens
        for cid in chain_ids:
            all_targets.extend(self.discover_suspicious_tokens(cid, pages=2))
        # Channel 10: Same-category-as-recently-hacked (pattern matching)
        all_targets.extend(self.discover_defillama_recent_hacks())
        # Deduplicate (keep highest priority)
        seen = {}
        for t in all_targets:
            key = (t.address.lower(), t.chain_id)
            if key not in seen or t.priority > seen[key].priority:
                seen[key] = t
        deduped = list(seen.values())
        deduped.sort(key=lambda x: x.priority, reverse=True)
        print(f"[DISCOVERY] Total: {len(all_targets)} raw -> {len(deduped)} unique targets")
        return deduped

    def _resolve_chain_ids(self, proto_chains, filter_chains=None):
        name_to_id = {v["name"].lower(): k for k, v in CHAINS.items()}
        name_to_id.update({v["short"]: k for k, v in CHAINS.items()})
        ids = []
        for c in (proto_chains or []):
            cid = name_to_id.get(c.lower())
            if cid and (filter_chains is None or cid in filter_chains):
                ids.append(cid)
        return ids or ([filter_chains[0]] if filter_chains else [])

    def _is_defi_like(self, contract_name, compiler_version=""):
        if not contract_name:
            return False
        name_lower = contract_name.lower()
        defi_patterns = [
            "pool", "vault", "lending", "borrow", "swap", "exchange",
            "staking", "yield", "farm", "liquidity", "amm", "dex",
            "router", "factory", "pair", "governance", "treasury",
            "bridge", "oracle", "price", "feed", "aggregator",
            "margin", "perp", "option", "future", "leverage",
            "deposit", "withdraw", "collateral", "flashloan", "strategy", "harvest",
        ]
        blacklist = ["nft", "erc721", "erc1155", "multicall", "proxy", "clone", "beacon"]
        if len(name_lower.split("_")) <= 1 and len(contract_name) < 5:
            return False
        is_defi = any(p in name_lower for p in defi_patterns)
        is_blacklisted = any(p in name_lower for p in blacklist)
        return is_defi and not is_blacklisted
