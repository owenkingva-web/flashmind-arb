r"""T3-3 Governance Vulnerability Scanner

Dedicated scanner for governance-related vulnerabilities:
- Zero proposal threshold
- Missing guardian/timelock
- EOA admin keys
- Instant execution (no delay)
- Quorum too low
"""
import re
from web3 import Web3
from .config import CHAINS
from .analyzer import Finding


class GovernanceScanner:
    """Scan governance contracts for takeover vulnerabilities."""

    # Common governor function signatures
    GOV_VIEW_SIGS = {
        'proposalThreshold': 'proposalThreshold() returns (uint256)',
        'quorumNumerator': 'quorumNumerator() returns (uint256)',
        'quorumVotes': 'quorumVotes(uint256) returns (uint256)',
        'votingDelay': 'votingDelay() returns (uint256)',
        'votingPeriod': 'votingPeriod() returns (uint256)',
        'timelock': 'timelock() returns (address)',
        'guardian': 'guardian() returns (address)',
        'admin': 'admin() returns (address)',
        'owner': 'owner() returns (address)',
        'getVotes': 'getVotes(address) returns (uint256)',
        'state': 'state(uint256) returns (uint256)',
    }

    def scan_governance(self, address: str, chain_id: int,
                          source_code: str = None) -> list:
        """Comprehensive governance vulnerability scan."""
        findings = []
        chain = CHAINS.get(chain_id)
        if not chain:
            return findings

        # On-chain checks
        try:
            w3 = Web3(Web3.HTTPProvider(
                chain['rpc'], request_kwargs={'timeout': 15}
            ))
            if w3.is_connected():
                findings.extend(self._on_chain_gov_scan(w3, address))
        except Exception:
            pass

        # Source code checks
        if source_code:
            findings.extend(self._source_gov_scan(source_code, address))

        return findings

    def _on_chain_gov_scan(self, w3: Web3, address: str) -> list:
        """Query governance functions on-chain."""
        findings = []
        addr = Web3.to_checksum_address(address)

        # Read key values
        values = {}
        for name, sig in self.GOV_VIEW_SIGS.items():
            try:
                func_sig = sig.split(' returns ')[0].strip()
                selector = Web3.keccak(text=func_sig)[:4]
                result = w3.eth.call({'to': addr, 'data': selector})
                if result != bytes(32):
                    if 'address' in sig.lower():
                        val = Web3.to_checksum_address('0x' + result[12:].hex())
                        if int(val, 16) > 0:
                            values[name] = val
                    elif 'uint256' in sig.lower():
                        val = int.from_bytes(result, 'big')
                        if val > 0:
                            values[name] = val
            except Exception:
                pass

        # Check for zero proposal threshold
        pt = values.get('proposalThreshold')
        if pt is not None and pt == 0:
            findings.append(Finding(
                vuln_id='GOV-ONCHAIN-01', category='Governance',
                severity='CRITICAL',
                title='Zero proposal threshold (confirmed on-chain)',
                description='proposalThreshold() returns 0. Anyone can create governance proposals without any tokens. Term Finance $8.5M exploit used this exact vector.',
                location=f'{address}:proposalThreshold()', confidence=0.98,
                zero_capital=True,
                attack_scenario='1. Create malicious proposal -> 2. Execute via missing timelock -> 3. Drain funds',
                source='governance_scanner',
            ))
        elif pt is not None and pt < 1000:
            findings.append(Finding(
                vuln_id='GOV-ONCHAIN-02', category='Governance',
                severity='HIGH',
                title=f'Very low proposal threshold: {pt}',
                description=f'proposalThreshold() returns {pt}. Very cheap to create proposals.',
                location=f'{address}:proposalThreshold()', confidence=0.9,
                zero_capital=True, source='governance_scanner',
            ))

        # Check quorum
        qn = values.get('quorumNumerator')
        if qn is not None and qn < 4:
            findings.append(Finding(
                vuln_id='GOV-ONCHAIN-03', category='Governance',
                severity='HIGH',
                title=f'Very low quorum numerator: {qn}',
                description=f'quorumNumerator() returns {qn}. Very few votes needed to pass proposals.',
                location=f'{address}:quorumNumerator()', confidence=0.85,
                zero_capital=True, source='governance_scanner',
            ))

        # Check timelock
        tl = values.get('timelock')
        if not tl:
            findings.append(Finding(
                vuln_id='GOV-ONCHAIN-04', category='Governance',
                severity='CRITICAL',
                title='No timelock set on governor',
                description='Governor has no timelock. Proposals execute immediately after passing, leaving no reaction window.',
                location=address, confidence=0.9, zero_capital=True,
                source='governance_scanner',
            ))
        else:
            # Check if timelock is actually a contract
            try:
                tl_code = w3.eth.get_code(Web3.to_checksum_address(tl))
                if len(tl_code) <= 2:
                    findings.append(Finding(
                        vuln_id='GOV-ONCHAIN-05', category='Governance',
                        severity='CRITICAL',
                        title=f'Timelock is EOA: {tl}',
                        description=f'Timelock address {tl} has no code - it is an EOA. Instant execution possible.',
                        location=address, confidence=0.95, zero_capital=True,
                        source='governance_scanner',
                    ))
            except Exception:
                pass

        # Check guardian
        guardian = values.get('guardian') or values.get('admin')
        if guardian:
            try:
                g_code = w3.eth.get_code(Web3.to_checksum_address(guardian))
                if len(g_code) <= 2:
                    role = 'guardian' if values.get('guardian') else 'admin'
                    findings.append(Finding(
                        vuln_id='GOV-ONCHAIN-06', category='Governance',
                        severity='HIGH',
                        title=f'{role.title()} is EOA: {guardian}',
                        description=f'The {role} is a regular wallet. Single key compromise = full governance control.',
                        location=address, confidence=0.9, source='governance_scanner',
                    ))
            except Exception:
                pass

        # Check owner
        owner = values.get('owner')
        if owner:
            try:
                o_code = w3.eth.get_code(Web3.to_checksum_address(owner))
                if len(o_code) <= 2:
                    findings.append(Finding(
                        vuln_id='GOV-ONCHAIN-07', category='Governance',
                        severity='HIGH',
                        title=f'Owner is EOA: {owner}',
                        description='Contract owner is a regular wallet, not a multisig. Single key compromise = full control.',
                        location=address, confidence=0.9, source='governance_scanner',
                    ))
            except Exception:
                pass

        return findings

    def _source_gov_scan(self, source: str, address: str) -> list:
        """Scan source code for governance anti-patterns."""
        findings = []
        code = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

        # Check for missing access control on critical gov functions
        gov_functions = {
            'execute': 'proposal execution',
            '_execute': 'internal proposal execution',
            'cancel': 'proposal cancellation',
            'queue': 'proposal queuing',
        }

        for func_name, desc in gov_functions.items():
            pattern = rf'function\s+{func_name}\s*\([^)]*\)\s*(external|public)'
            m = re.search(pattern, code, re.IGNORECASE)
            if m:
                func_start = m.start()
                func_ctx = code[func_start:func_start + 500]
                has_guard = bool(re.search(
                    r'onlyGovernor|onlyRole|_checkRole|onlyTimelock|require\(.*msg\.sender',
                    func_ctx
                ))
                if not has_guard:
                    findings.append(Finding(
                        vuln_id='GOV-SRC-01', category='Governance',
                        severity='CRITICAL',
                        title=f'Unprotected {desc}: {func_name}()',
                        description=f'{func_name}() has no access control. Anyone can {desc}.',
                        location=f'{address}:{func_name}()', confidence=0.8,
                        zero_capital=True, source='governance_scanner',
                    ))

        # Check for missing guardian in OpenZeppelin Governor
        if re.search(r'Governor|GovernorCompatibility', code):
            if not re.search(r'guardian\s*\(|setGuardian|_setGuardian', code):
                findings.append(Finding(
                    vuln_id='GOV-SRC-02', category='Governance',
                    severity='MEDIUM',
                    title='Governor without guardian',
                    description='Uses OpenZeppelin Governor but no guardian set. Guardian is the last line of defense against proposal execution bugs.',
                    location=address, confidence=0.6, source='governance_scanner',
                ))

        return findings
