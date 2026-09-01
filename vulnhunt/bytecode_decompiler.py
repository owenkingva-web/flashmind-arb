r"""T3-3 Unverified Contract Analyzer

Handles contracts where source code is NOT verified on block explorers.
Strategies:
1. Bytecode pattern matching for known vulnerability signatures
2. Function selector extraction and dangerous function detection
3. Storage slot analysis for proxy patterns
4. Bytecode decompilation attempts (heimdall-rs if available)
5. ABI recovery from function selectors using 4byte.directory

This is critical because many new buggy protocols don't verify immediately.
"""
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional
from web3 import Web3
import requests

from .config import CHAINS
from .analyzer import Finding


@dataclass
class BytecodeAnalysis:
    address: str
    chain_id: int
    bytecode: str
    is_proxy: bool = False
    implementation_slot: str = ""
    has_selfdestruct: bool = False
    has_delegatecall: bool = False
    has_create: bool = False
    has_reentrancy_pattern: bool = False
    function_selectors: list = field(default_factory=list)
    storage_layout: dict = field(default_factory=dict)
    risk_signals: list = field(default_factory=list)
    decompiled_source: str = ""
    findings: list = field(default_factory=list)


class BytecodeAnalyzer:
    """Analyze unverified contract bytecode for vulnerability signals."""

    def __init__(self):
        self._w3_cache = {}
        self._4byte_cache = {}
        self._heimdall_available = self._check_heimdall()

    def _check_heimdall(self) -> bool:
        """Check if heimdall-rs is installed for decompilation."""
        try:
            result = subprocess.run(
                ['heimdall', '--version'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_w3(self, chain_id: int) -> Web3:
        if chain_id not in self._w3_cache:
            chain = CHAINS.get(chain_id, {})
            w3 = Web3(Web3.HTTPProvider(chain['rpc'], request_kwargs={'timeout': 30}))
            self._w3_cache[chain_id] = w3
        return self._w3_cache[chain_id]

    def analyze_unverified(self, address: str, chain_id: int) -> BytecodeAnalysis:
        """Full analysis of an unverified contract."""
        w3 = self._get_w3(chain_id)
        addr = Web3.to_checksum_address(address)

        # Get bytecode
        try:
            bytecode = w3.eth.get_code(addr).hex()
        except Exception as e:
            return BytecodeAnalysis(address=address, chain_id=chain_id, bytecode='')

        if not bytecode or bytecode == '0x' or len(bytecode) < 20:
            return BytecodeAnalysis(address=address, chain_id=chain_id, bytecode=bytecode)

        analysis = BytecodeAnalysis(
            address=address,
            chain_id=chain_id,
            bytecode=bytecode,
        )

        print(f'[BYTECODE] Analyzing {address[:10]}... ({len(bytecode)} bytes)')

        # 1. Check for proxy patterns (EIP-1967)
        analysis.is_proxy = self._check_proxy(w3, addr)

        # 2. Bytecode pattern analysis
        self._detect_bytecode_patterns(analysis)

        # 3. Extract function selectors
        analysis.function_selectors = self._extract_selectors(bytecode)

        # 4. Lookup selectors in 4byte.directory
        self._lookup_selectors(analysis)

        # 5. Storage slot analysis
        analysis.storage_layout = self._analyze_storage(w3, addr)

        # 6. Try decompilation
        if self._heimdall_available:
            analysis.decompiled_source = self._decompile_heimdall(bytecode)

        # 7. Generate findings
        analysis.findings = self._generate_findings(analysis, address, chain_id)

        print(f'[BYTECODE] {address[:10]}...: {len(analysis.findings)} findings, '
              f'proxy={analysis.is_proxy}, selectors={len(analysis.function_selectors)}')

        return analysis

    def _check_proxy(self, w3: Web3, address: str) -> bool:
        """Check EIP-1967 implementation slot."""
        impl_slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
        admin_slot = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103'

        try:
            impl = w3.eth.get_storage_at(address, impl_slot)
            admin = w3.eth.get_storage_at(address, admin_slot)

            if impl != b'\x00' * 32:
                self._last_impl_slot = '0x' + impl[-20:].hex()
                return True
            if admin != b'\x00' * 32:
                return True
        except Exception:
            pass

        return False

    def _detect_bytecode_patterns(self, analysis: BytecodeAnalysis):
        """Detect vulnerability patterns in raw bytecode."""
        bc = analysis.bytecode

        # Selfdestruct: opcode 0xFF
        if 'ff' in self._extract_opcodes(bc):
            analysis.has_selfdestruct = True
            analysis.risk_signals.append(('SELFDESTRUCT', 'CRITICAL', 'selfdestruct opcode detected'))

        # Delegatecall: opcode 0xF4
        if 'f4' in self._extract_opcodes(bc):
            analysis.has_delegatecall = True
            analysis.risk_signals.append(('DELEGATECALL', 'HIGH', 'delegatecall opcode detected'))

        # CREATE/CREATE2: opcodes 0xF0/0xF5
        opcodes = self._extract_opcodes(bc)
        if 'f0' in opcodes or 'f5' in opcodes:
            analysis.has_create = True

        # Reentrancy pattern: CALL/STATICCALL followed by SSTORE in same function
        # This is a simplified heuristic - real detection needs CFG analysis
        call_ops = {'f1', 'fa'}  # CALL, STATICCALL
        sstore_op = '55'
        if call_ops & set(opcodes) and sstore_op in opcodes:
            analysis.has_reentrancy_pattern = True
            analysis.risk_signals.append(('REENTRANCY_RISK', 'HIGH', 'CALL + SSTORE pattern detected'))

        # Uniswap V2 pair detection (common attack target)
        if '0x5c69bee701ef814a2b6aedd4b1652cb9cc5aa6f' in bc.lower():
            analysis.risk_signals.append(('UNISWAP_PAIR', 'INFO', 'Contains Uniswap V2 factory reference'))

    def _extract_opcodes(self, bytecode: str) -> list:
        """Extract opcodes from bytecode for pattern matching."""
        opcodes = []
        # Simple extraction - take every 2 chars as potential opcode
        # (not perfectly accurate but good enough for common patterns)
        i = 2  # skip 0x
        while i < len(bytecode) - 2:
            opcodes.append(bytecode[i:i+2])
            i += 2
        return opcodes

    def _extract_selectors(self, bytecode: str) -> list:
        """Extract 4-byte function selectors from PUSH4 (0x63) instructions.

        When Solidity compiles, it uses PUSH4 to push function selectors
        onto the stack for dispatch. We can extract these.
        """
        selectors = []
        i = 0
        while i < len(bytecode) - 10:
            # PUSH4 = 0x63, followed by 4 bytes of selector
            if bytecode[i:i+2] == '63':
                selector = '0x' + bytecode[i+2:i+10]
                if selector not in selectors and selector != '0x00000000':
                    selectors.append(selector)
                i += 10
            else:
                i += 2

        return selectors

    def _lookup_selectors(self, analysis: BytecodeAnalysis):
        """Lookup function selectors in 4byte.directory and openchain.

        This recovers function names and parameter types even for
        unverified contracts.
        """
        known_dangerous = {
            '0x2e1a7d4d': 'withdraw(uint256)',
            '0x3ccfd60b': 'withdraw()',
            '0xf2fde38b': 'transferOwnership(address)',
            '0x3659cfe6': 'upgradeTo(address)',
            '0x42966c68': 'selfdestruct(address)',
            '0x5c975abb': 'paused() returns (bool)',
            '0x8f283970': 'withdrawAll()',
            '0xa217fddf': 'DEFAULT_ADMIN_ROLE()',
            '0xd547741f': 'grantRole(bytes32,address)',
            '0x2f2ff15d': 'revokeRole(bytes32,address)',
            '0x01ffc9a7': 'supportsInterface(bytes4)',
            '0x248a9ca3': 'getRoleAdmin(bytes32)',
            '0x36568abe': 'renounceRole(bytes32,address)',
            '0x9010d07c': 'nonReentrant()',
            '0x42966c68': 'destroy()',
        }

        dangerous_found = []
        for selector in analysis.function_selectors:
            if selector in known_dangerous:
                dangerous_found.append(f"{selector} = {known_dangerous[selector]}")

        # Try 4byte.directory for unknown selectors
        unknown = [s for s in analysis.function_selectors if s not in known_dangerous]
        for selector in unknown[:10]:  # Limit API calls
            sig = self._lookup_4byte(selector)
            if sig:
                dangerous_found.append(f"{selector} = {sig}")

        if dangerous_found:
            analysis.risk_signals.append(
                ('DANGEROUS_SELECTORS', 'HIGH',
                 f'Functions found: {dangerous_found}')
            )

    def _lookup_4byte(self, selector: str) -> Optional[str]:
        """Lookup a function selector on 4byte.directory."""
        if selector in self._4byte_cache:
            return self._4byte_cache[selector]

        try:
            resp = requests.get(
                f'https://www.4byte.directory/api/v1/signatures/?hex_signature={selector}',
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('results'):
                    sig = data['results'][0].get('text_signature', '')
                    self._4byte_cache[selector] = sig
                    return sig
        except Exception:
            pass

        return None

    def _analyze_storage(self, w3: Web3, address: str) -> dict:
        """Read key storage slots for state analysis."""
        layout = {}

        # Common storage slots
        slots = {
            'owner': '0x' + '00' * 31 + '01',
            'paused': '0x' + '00' * 31 + '08',
            'totalSupply': '0x' + '00' * 31 + '09',
        }

        for name, slot in slots.items():
            try:
                value = w3.eth.get_storage_at(address, slot)
                layout[name] = '0x' + value.hex()
            except Exception:
                pass

        return layout

    def _decompile_heimdall(self, bytecode: str) -> str:
        """Attempt decompilation using heimdall-rs."""
        try:
            result = subprocess.run(
                ['heimdall', 'decompile', bytecode],
                capture_output=True, timeout=60
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.decode()
        except Exception:
            pass
        return ''

    def _generate_findings(self, analysis: BytecodeAnalysis, address: str,
                            chain_id: int) -> list:
        """Convert risk signals into Finding objects."""
        findings = []

        for signal_name, severity, description in analysis.risk_signals:
            zero_cap = severity in ('CRITICAL', 'HIGH')
            flash = 'REENTRANCY' in signal_name or 'ORACLE' in signal_name

            finding = Finding(
                vuln_id=f'BYTE-{signal_name[:8]}',
                category=self._signal_to_category(signal_name),
                severity=severity,
                title=f'[Bytecode] {signal_name}: {description[:60]}',
                description=f'Unverified contract {address[:10]}... on chain {chain_id}: {description}',
                location=f'{address} (unverified bytecode)',
                confidence=0.5,  # Lower confidence for bytecode-only analysis
                zero_capital=zero_cap,
                flash_loan_required=flash,
                source='bytecode',
                raw_data={'function_selectors': analysis.function_selectors},
            )
            findings.append(finding)

        # Bonus: if proxy without verified implementation, flag it
        if analysis.is_proxy and not analysis.decompiled_source:
            findings.append(Finding(
                vuln_id='BYTE-PROXY',
                category='Proxy',
                severity='HIGH',
                title='[Bytecode] Unverified proxy contract',
                description=f'Proxy at {address} with no verified implementation source',
                location=f'{address} (proxy)',
                confidence=0.9,
                zero_capital=True,
                source='bytecode',
            ))

        return findings

    def _signal_to_category(self, signal: str) -> str:
        mapping = {
            'SELFDESTRUCT': 'Selfdestruct',
            'DELEGATECALL': 'Unsafe Delegatecall',
            'REENTRANCY_RISK': 'Reentrancy',
            'DANGEROUS_SELECTORS': 'Access Control',
            'UNISWAP_PAIR': 'DEX Interaction',
        }
        return mapping.get(signal, 'Unknown')
