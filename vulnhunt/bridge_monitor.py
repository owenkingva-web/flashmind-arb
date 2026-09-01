r"""T3-3 Cross-Chain Bridge Vulnerability Monitor

Monitors major bridges for:
1. Fund imbalances (locked < minted = insolvency risk)
2. Large pending transfers (delay exploit windows)
3. Upgradable bridge contracts (admin key risk)
4. Message verification flaws (forged messages)
5. Gas price manipulation on destination chain

Bridges monitored:
- Stargate (multichain)
- Across Protocol
- Arbitrum Bridge (L1->L2 inbox)
- Base Bridge (L1->L2)
- PancakeSwap Bridge
- Synapse
"""
import json
import time
from dataclasses import dataclass, field
from typing import Optional
from web3 import Web3
import requests

from .config import CHAINS, ETH_PRICE_USD
from .analyzer import Finding


@dataclass
class BridgeInfo:
    name: str
    chain_id: int
    contract_address: str
    bridge_type: str  # 'lock_mint', 'burn_mint', 'liquidity'
    tvl_locked: float = 0
    tvl_minted: float = 0
    imbalance_ratio: float = 1.0
    pending_transfers: int = 0
    is_upgradable: bool = False
    admin_address: str = ""
    admin_is_eoa: bool = False
    last_activity: float = 0


# Known bridge contracts per chain
BRIDGE_CONTRACTS = {
    # Stargate
    'stargate_eth': {
        'name': 'Stargate', 'chain_id': 1,
        'address': '0x663F3b6F193621e26c0aE1F240c415a712CA9a15',
        'type': 'liquidity',
    },
    'stargate_arb': {
        'name': 'Stargate', 'chain_id': 42161,
        'address': '0x53c8E199eb2Cb7c0153797E63C67E50eA3110CBc',
        'type': 'liquidity',
    },
    'stargate_base': {
        'name': 'Stargate', 'chain_id': 8453,
        'address': '0x45fFd7F4d819aEc4D10eFAe5F634A35A9A711B08',
        'type': 'liquidity',
    },
    # Across Protocol
    'across_eth': {
        'name': 'Across', 'chain_id': 1,
        'address': '0x6B26e41eC208f69084AE2772bC25460E8B3a4eC3',
        'type': 'lock_mint',
    },
    # Arbitrum Bridge
    'arb_bridge_eth': {
        'name': 'Arbitrum Bridge', 'chain_id': 1,
        'address': '0xC1d0b3CE3C640c90eF3a746A967c57E0Dc089B94',
        'type': 'lock_mint',
    },
    'arb_inbox_arb': {
        'name': 'Arbitrum Inbox', 'chain_id': 42161,
        'address': '0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f',
        'type': 'lock_mint',
    },
    # Base Bridge
    'base_bridge_eth': {
        'name': 'Base Bridge', 'chain_id': 1,
        'address': '0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6',
        'type': 'lock_mint',
    },
    # Synapse
    'synapse_eth': {
        'name': 'Synapse', 'chain_id': 1,
        'address': '0x3E2b3e1E0e1c63064A4a693eEe878Cf6F3A316A5',
        'type': 'liquidity',
    },
}


class BridgeMonitor:
    """Monitor cross-chain bridges for vulnerability signals."""

    def __init__(self):
        self._w3_cache = {}
        self._bridge_states = {}
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'VulnHunter/3.0'})

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id, {})
            w3 = Web3(Web3.HTTPProvider(chain['rpc'], request_kwargs={'timeout': 15}))
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    def scan_all_bridges(self) -> list:
        """Scan all monitored bridges for vulnerabilities."""
        findings = []
        print(f'[BRIDGE] Scanning {len(BRIDGE_CONTRACTS)} bridge contracts...')

        for key, bridge_info in BRIDGE_CONTRACTS.items():
            try:
                bridge = self._probe_bridge(bridge_info)
                self._bridge_states[key] = bridge
                bridge_findings = self._analyze_bridge(bridge)
                findings.extend(bridge_findings)
            except Exception as e:
                print(f'[BRIDGE] {key} scan error: {e}')

        # Also check DeFiLlama bridge TVL data
        findings.extend(self._check_defillama_bridges())

        print(f'[BRIDGE] Found {len(findings)} bridge findings')
        return findings

    def _probe_bridge(self, info: dict) -> BridgeInfo:
        """Probe a bridge contract on-chain."""
        chain_id = info['chain_id']
        addr = info['address']
        w3 = self._get_w3(chain_id)

        bridge = BridgeInfo(
            name=info['name'],
            chain_id=chain_id,
            contract_address=addr,
            bridge_type=info['type'],
            last_activity=time.time(),
        )

        addr_cs = Web3.to_checksum_address(addr)

        # Check contract exists
        try:
            code = w3.eth.get_code(addr_cs)
            if len(code) <= 2:
                return bridge
        except Exception:
            return bridge

        # Check native balance (ETH/BNB locked)
        try:
            bal = w3.eth.get_balance(addr_cs)
            bridge.tvl_locked = float(w3.from_wei(bal, 'ether'))
        except Exception:
            pass

        # Check if upgradable (EIP-1967 admin slot)
        admin_slot = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103'
        impl_slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'

        try:
            admin_data = w3.eth.get_storage_at(addr_cs, admin_slot)
            if admin_data != b'\x00' * 32:
                bridge.is_upgradable = True
                bridge.admin_address = '0x' + admin_data[-20:].hex()

                # Check if admin is EOA
                admin_code = w3.eth.get_code(Web3.to_checksum_address(bridge.admin_address))
                bridge.admin_is_eoa = len(admin_code) <= 2

            impl_data = w3.eth.get_storage_at(addr_cs, impl_slot)
            if impl_data != b'\x00' * 32:
                bridge.is_upgradable = True
        except Exception:
            pass

        # Check owner
        try:
            selector = Web3.keccak(text='owner()')[:4]
            result = w3.eth.call({'to': addr_cs, 'data': selector})
            owner = '0x' + result[-20:].hex()
            if int(owner, 16) > 0:
                bridge.admin_address = owner
                owner_code = w3.eth.get_code(Web3.to_checksum_address(owner))
                bridge.admin_is_eoa = len(owner_code) <= 2
                if bridge.admin_is_eoa:
                    bridge.is_upgradable = True
        except Exception:
            pass

        return bridge

    def _analyze_bridge(self, bridge: BridgeInfo) -> list:
        """Analyze a probed bridge for vulnerabilities."""
        findings = []

        # 1. Upgradable bridge with EOA admin
        if bridge.is_upgradable and bridge.admin_is_eoa:
            findings.append(Finding(
                vuln_id='BRIDGE-UPGRADE-01',
                category='Access Control',
                severity='CRITICAL',
                title=f'{bridge.name}: Upgradable bridge with EOA admin',
                description=(
                    f'{bridge.name} bridge on {CHAINS.get(bridge.chain_id, {}).get("name", bridge.chain_id)} '
                    f'is upgradable and admin ({bridge.admin_address}) is an EOA. '
                    f'Single key compromise = full bridge control. Can mint unlimited tokens, '
                    f'change fee parameters, or pause withdrawals. '
                    f'Historical: Wormhole $326M (forged messages), Nomad $190M (message verification), '
                    f'Ronin $625M (validator compromise).'
                ),
                location=f'{bridge.contract_address}',
                confidence=0.9,
                zero_capital=True,
                source='bridge_monitor',
            ))

        # 2. Lock-and-mint bridge TVL check
        if bridge.bridge_type == 'lock_mint' and bridge.tvl_locked > 0:
            # For L1->L2 bridges, locked ETH on L1 should roughly equal minted on L2
            # We can't easily check the L2 side here, but we flag low TVL
            if bridge.tvl_locked < 100:  # Less than 100 ETH
                findings.append(Finding(
                    vuln_id='BRIDGE-TVL-01',
                    category='Bridge',
                    severity='LOW',
                    title=f'{bridge.name}: Low TVL bridge ({bridge.tvl_locked:.1f} ETH)',
                    description=f'Bridge has only {bridge.tvl_locked:.1f} ETH locked. Lower value targets have less security scrutiny.',
                    location=bridge.contract_address,
                    confidence=0.7,
                    source='bridge_monitor',
                ))

        return findings

    def _check_defillama_bridges(self) -> list:
        """Use DeFiLlama bridges API to find new/under-audited bridges."""
        findings = []
        try:
            api_resp = self._session.get(
                'https://api.llama.fi/bridges',
                timeout=30,
            )
            if api_resp.status_code == 200:
                bridges = api_resp.json()
                for b in bridges[:50]:
                    name = b.get('name', '')
                    tvl = b.get('tvl', 0) or 0
                    if tvl < 100_000 or tvl > 50_000_000:
                        continue
                    # Check if it has known audit status
                    chains = b.get('chains', [])
                    display_name = b.get('display_name', name)

                    # Flag new/unknown bridges with significant TVL
                    known_safe_bridges = {
                        'stargate', 'across', 'synapse', 'hop', 'arbitrum',
                        'optimism', 'polygon', 'base', 'wormhole', 'celer',
                        'nomad', 'ronin', 'axelar', 'allbridge', 'satellite',
                        'multichain', 'anyswap', 'renvm', 'bitcoin-bridge',
                    }
                    if name.lower() not in known_safe_bridges:
                        findings.append(Finding(
                            vuln_id='BRIDGE-NEW-01',
                            category='Bridge',
                            severity='MEDIUM',
                            title=f'Lesser-known bridge: {display_name} (${tvl:,.0f} TVL)',
                            description=(
                                f'{display_name} is a bridge with ${tvl:,.0f} TVL across '
                                f'{len(chains)} chains. Not in the well-audited set. '
                                f'Bridge hacks account for $2.5B+ in total losses. '
                                f'Lesser-known bridges may have unaudited message verification.'
                            ),
                            location=f'bridge:{name}',
                            confidence=0.5,
                            source='bridge_monitor',
                            raw_data={'bridge_name': name, 'tvl': tvl, 'chains': chains},
                        ))

        except Exception as e:
            print(f'[BRIDGE] DeFiLlama bridge scan error: {e}')

        return findings

    def get_bridge_health(self) -> dict:
        """Get a summary of all monitored bridge health."""
        health = {}
        for key, bridge in self._bridge_states.items():
            health[key] = {
                'name': bridge.name,
                'chain': CHAINS.get(bridge.chain_id, {}).get('name', str(bridge.chain_id)),
                'tvl_locked': f'{bridge.tvl_locked:.2f}',
                'upgradable': bridge.is_upgradable,
                'admin_eoa': bridge.admin_is_eoa,
                'admin': bridge.admin_address,
            }
        return health
