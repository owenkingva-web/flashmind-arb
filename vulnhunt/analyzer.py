"""T3-3 Dual-Engine Vulnerability Analyzer

Engine 1: Slither AST analysis
Engine 2: Regex pattern matching
Engine 3: ABI deep inspection
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from .config import SEVERITY_ORDER
from .db import Database
from .fetcher import SourceFetcher


@dataclass
class Finding:
    vuln_id: str
    category: str
    severity: str
    title: str
    description: str
    location: str
    confidence: float = 0.5
    zero_capital: bool = False
    flash_loan_required: bool = False
    estimated_gas: int = 0
    attack_scenario: str = ''
    remediation: str = ''
    references: list = field(default_factory=list)
    source: str = 'regex'
    raw_data: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            'vuln_id': self.vuln_id, 'category': self.category,
            'severity': self.severity, 'title': self.title,
            'description': self.description, 'location': self.location,
            'confidence': self.confidence, 'zero_capital': self.zero_capital,
            'flash_loan_required': self.flash_loan_required,
            'estimated_gas': self.estimated_gas,
            'attack_scenario': self.attack_scenario,
            'remediation': self.remediation, 'references': self.references,
            'source': self.source, 'raw_data': self.raw_data,
        }


class VulnerabilityAnalyzer:
    def __init__(self, db: Database = None):
        self.db = db
        self.fetcher = SourceFetcher(db)
        self.findings = []
        self._slither_available = self._check_slither()

    def _check_slither(self):
        try:
            result = subprocess.run(
                ['slither', '--version'], capture_output=True, timeout=10,
                env={**os.environ, 'PATH': f"{os.path.expanduser('~/.local/bin')}:{os.environ.get('PATH', '')}"}
            )
            return result.returncode == 0
        except Exception:
            return False

    def analyze_contract(self, address, chain_id, source_data=None):
        self.findings = []
        if not source_data:
            source_data = self.fetcher.fetch_source(address, chain_id)
        if not source_data:
            return self.findings
        source_code = source_data.get('source_code', '')
        contract_name = source_data.get('contract_name', '')
        abi_parsed = source_data.get('abi_parsed', [])
        if not source_code or len(source_code) < 50:
            return self.findings
        code_clean = self._clean_source(source_code)
        self.findings.extend(self._run_slither(source_data, address))
        self.findings.extend(self._run_regex_analysis(code_clean, contract_name))
        if abi_parsed:
            self.findings.extend(self._run_abi_analysis(abi_parsed, contract_name, code_clean))
        self._deduplicate()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence))
        return self.findings

    def _run_slither(self, source_data, address):
        if not self._slither_available:
            return []
        findings = []
        tmp_dir = self.fetcher.prepare_source_for_slither(source_data, address)
        if not tmp_dir:
            return []
        try:
            env = {**os.environ, 'PATH': f"{os.path.expanduser('~/.local/bin')}:{os.environ.get('PATH', '')}"}
            result = subprocess.run(
                ['slither', tmp_dir, '--json', '-', '--disable-color'],
                capture_output=True, timeout=120, env=env,
            )
            if result.returncode == 0 and result.stdout:
                try:
                    slither_output = json.loads(result.stdout.decode())
                    findings = self._parse_slither_results(slither_output)
                except json.JSONDecodeError:
                    if result.stderr:
                        try:
                            findings = self._parse_slither_results(json.loads(result.stderr.decode()))
                        except Exception:
                            pass
            if not findings and result.stderr:
                findings = self._parse_slither_text(result.stderr.decode())
        except subprocess.TimeoutExpired:
            print(f'[ANALYZER] Slither timed out')
        except Exception as e:
            print(f'[ANALYZER] Slither error: {e}')
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if findings:
            print(f'[ANALYZER] Slither: {len(findings)} issues')
        return findings

    def _parse_slither_results(self, output):
        findings = []
        results = output.get('results', {})
        SLITHER_MAP = {
            'reentrancy-eth': ('REENT-001', 'Reentrancy', 'CRITICAL', True, True),
            'reentrancy-no-eth': ('REENT-002', 'Reentrancy', 'HIGH', True, False),
            'unprotected-upgrade': ('ACCESS-001', 'Access Control', 'CRITICAL', True, False),
            'auth-through-anyone': ('ACCESS-002', 'Access Control', 'HIGH', True, False),
            'unprotected-selfdestruct': ('SELF-001', 'Selfdestruct', 'CRITICAL', True, False),
            'arbitrary-send-erc20': ('ACCESS-003', 'Access Control', 'HIGH', True, False),
            'arbitrary-send-eth': ('ACCESS-004', 'Access Control', 'CRITICAL', True, False),
            'delegatecall-loop': ('DELG-001', 'Unsafe Delegatecall', 'CRITICAL', True, False),
            'tx-origin-usage': ('ACCESS-005', 'Access Control', 'MEDIUM', True, False),
            'uninitialized-state': ('INIT-001', 'Initialization', 'CRITICAL', True, False),
            'unchecked-transfer': ('ERC20-001', 'Unsafe ERC20', 'MEDIUM', False, False),
            'flashloan-eth': ('FLASH-001', 'Flash Loan Exposure', 'MEDIUM', True, True),
        }
        for check_id, check_data in results.items():
            check_lower = check_id.lower()
            mapped = None
            for pattern, map_data in SLITHER_MAP.items():
                if pattern in check_lower:
                    mapped = map_data
                    break
            if not mapped:
                if 'reentrancy' in check_lower:
                    mapped = ('REENT-UNK', 'Reentrancy', 'HIGH', True, True)
                elif 'access' in check_lower or 'auth' in check_lower:
                    mapped = ('ACCESS-UNK', 'Access Control', 'HIGH', True, False)
                elif 'oracle' in check_lower or 'price' in check_lower:
                    mapped = ('ORACLE-UNK', 'Oracle Manipulation', 'CRITICAL', True, True)
                elif 'delegatecall' in check_lower:
                    mapped = ('DELG-UNK', 'Unsafe Delegatecall', 'CRITICAL', True, False)
                else:
                    continue
            vuln_id, category, severity, zero_cap, flash = mapped
            for instance in check_data.get('description', []):
                if isinstance(instance, dict):
                    desc = instance.get('description', '') or instance.get('first_markdown_element', '')
                    loc = instance.get('filename', str(instance.get('first_markdown_element', ''))[:200])
                    confidence = 0.8 if severity in ('CRITICAL', 'HIGH') else 0.7
                    findings.append(Finding(
                        vuln_id=vuln_id, category=category, severity=severity,
                        title=f'[Slither] {check_id}',
                        description=str(desc)[:1000] if desc else f'Slither: {check_id}',
                        location=loc[:200], confidence=confidence,
                        zero_capital=zero_cap, flash_loan_required=flash,
                        source='slither', raw_data={'slither_check': check_id},
                    ))
        return findings

    def _parse_slither_text(self, text):
        findings = []
        patterns = [
            (r'Reentrancy in (\w+)', 'REENT-001', 'Reentrancy', 'CRITICAL'),
            (r'Unchecked\s+(?:low-level\s+)?call', 'REENT-004', 'Reentrancy', 'HIGH'),
            (r'Unprotected\s+(?:upgrade|selfdestruct)', 'SELF-001', 'Selfdestruct', 'CRITICAL'),
            (r'Anyone\s+can\s+(?:call|execute|withdraw)', 'ACCESS-002', 'Access Control', 'HIGH'),
        ]
        for pattern, vid, cat, sev in patterns:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                findings.append(Finding(
                    vuln_id=vid, category=cat, severity=sev,
                    title=f'[Slither] {m.group(0)[:100]}',
                    description=f'Slither: {m.group(0)}',
                    location='slither_output', confidence=0.6,
                    zero_capital=sev in ('CRITICAL', 'HIGH'), source='slither',
                ))
        return findings

    def _run_regex_analysis(self, code, contract):
        findings = []
        self._check_reentrancy(code, contract, findings)
        self._check_access_control(code, contract, findings)
        self._check_oracle_manipulation(code, contract, findings)
        self._check_flash_loan_exposure(code, contract, findings)
        self._check_delegatecall(code, contract, findings)
        self._check_initialization(code, contract, findings)
        self._check_selfdestruct(code, contract, findings)
        self._check_erc20_safety(code, contract, findings)
        self._check_rounding_errors(code, contract, findings)
        self._check_timelock(code, contract, findings)
        self._check_governance_patterns(code, contract, findings)
        self._check_integer_arithmetic(code, contract, findings)
        return findings

    def _check_reentrancy(self, code, contract, findings):
        sinks = [r'\.(call|transfer|send|delegatecall)\s*\(', r'IERC20.*\.transfer\s*\(']
        state_changes = [r'\w+\.\w+\s*\+=', r'\w+\.\w+\s*-=', r'_balances\[.*\]\s*=', r'_totalSupply\s*\+=']
        func_regex = r'function\s+(\w+)\s*\([^)]*\)\s*((?:external|public|internal|private)\s*(?:payable\s*)?(?:pure|view|)?)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
        functions = re.findall(func_regex, code, re.DOTALL)
        for func_name, modifiers, body in functions:
            if 'view' in modifiers or 'pure' in modifiers:
                continue
            if 'onlyOwner' in body or 'onlyRole' in body:
                continue
            has_ext = any(re.search(s, body) for s in sinks)
            has_state = any(re.search(c, body) for c in state_changes)
            has_guard = 'nonReentrant' in body or 'ReentrancyGuard' in body
            if has_ext and has_state and not has_guard:
                for sink in sinks:
                    for change in state_changes:
                        sm = re.search(sink, body)
                        cm = re.search(change, body)
                        if sm and cm and sm.start() < cm.start():
                            findings.append(Finding(
                                vuln_id='REENT-RX01', category='Reentrancy', severity='CRITICAL',
                                title=f'Reentrancy in {func_name}() - CEI violation',
                                description=f'{func_name}() external call before state update. No ReentrancyGuard. OWASP SC-01:2026. Curve $70M, Penpie $27M.',
                                location=f'{contract}:{func_name}()', confidence=0.7,
                                zero_capital=True, flash_loan_required=True, estimated_gas=300000,
                                attack_scenario='1. Flash loan -> 2. Call ' + func_name + '() -> 3. Re-enter -> 4. Repay',
                                remediation='Add nonReentrant. Follow CEI pattern.',
                                references=['OWASP SC-01:2026'], source='regex',
                            ))
                            return

    def _check_access_control(self, code, contract, findings):
        privileged = [
            (r'\._mint\s*\(', 'minting', 'CRITICAL'),
            (r'\.(setOwner|transferOwnership)\s*\(', 'ownership change', 'CRITICAL'),
            (r'\.(setFee|setFeeRate|setSwapFee)\s*\(', 'fee modification', 'HIGH'),
            (r'\.(setOracle|setPriceFeed)\s*\(', 'oracle modification', 'CRITICAL'),
            (r'\.(withdraw|withdrawAll|sweep)\s*\(', 'fund withdrawal', 'CRITICAL'),
            (r'\.(setImplementation|upgradeTo)\s*\(', 'proxy upgrade', 'CRITICAL'),
            (r'\.(grantRole|revokeRole)\s*\(', 'role management', 'HIGH'),
            (r'selfdestruct\s*\(', 'contract destruction', 'CRITICAL'),
        ]
        func_regex = r'function\s+(\w+)\s*\([^)]*\)\s*(external|public)\s*(payable\s*)?(?:pure\s*|view\s*)?\{'
        functions = re.findall(func_regex, code, re.DOTALL)
        for func_name, vis, pay in functions:
            full_vis = (vis + ' ' + (pay or '')).strip()
            if 'pure' in full_vis or 'view' in full_vis:
                continue
            func_start = code.find(f'function {func_name}')
            if func_start == -1:
                continue
            ctx = code[func_start:func_start + 2000]
            has_ac = bool(re.search(r'onlyOwner|onlyAdmin|onlyRole|AccessControl|_checkRole|if\s*\(msg\.sender\s*!=', ctx))
            for pattern, op_name, base_sev in privileged:
                if re.search(pattern, ctx) and not has_ac:
                    findings.append(Finding(
                        vuln_id='ACCESS-RX01', category='Access Control', severity=base_sev,
                        title=f'Unprotected {op_name} in {func_name}()',
                        description=f'{func_name}() performs {op_name} with NO access control. Term Finance $8.5M. Blockaid Aug 2026: $22M.',
                        location=f'{contract}:{func_name}()', confidence=0.85, zero_capital=True,
                        attack_scenario=f'Call {func_name}() directly.',
                        remediation='Add onlyOwner or role-based access control.',
                        references=['OWASP SC-05:2026'], source='regex',
                    ))
                    break

    def _check_oracle_manipulation(self, code, contract, findings):
        spot_prices = [
            (r'slot0\.(sqrtPriceX96|price)', 'Uniswap V3 slot0'),
            (r'getAmountsOut\s*\(', 'DEX getAmountsOut'),
            (r'reserve[0-9]\s*/\s*totalSupply', 'Direct reserve ratio'),
            (r'getReserves\s*\(\)', 'Uniswap V2 getReserves'),
        ]
        for pattern, desc in spot_prices:
            for m in re.finditer(pattern, code):
                ctx = code[max(0, m.start()-300):min(len(code), m.end()+300)]
                has_twap = bool(re.search(r'twap|TWAP|timeWeighted|cumulative', ctx, re.I))
                has_chainlink = bool(re.search(r'chainlink|latestRoundData', ctx, re.I))
                has_sanitizer = bool(re.search(r'sanitize|checkDeviation|maxDeviation|validatePrice', ctx, re.I))
                if not has_twap and not has_chainlink and not has_sanitizer:
                    findings.append(Finding(
                        vuln_id='ORACLE-RX01', category='Oracle Manipulation', severity='CRITICAL',
                        title=f'Manipulable oracle: {desc}',
                        description=f'{desc} used without TWAP/Chainlink/sanity check. MakinaFi $1.3M. Balancer V2 $128M. OWASP SC-03:2026.',
                        location=f'{contract}:{m.start()}', confidence=0.75,
                        zero_capital=True, flash_loan_required=True, estimated_gas=500000,
                        attack_scenario='1. Flash loan -> 2. Swap DEX -> 3. Call protocol -> 4. Profit -> 5. Reverse + repay',
                        remediation='Use Chainlink. TWAP >= 30min. Add maxDeviation check.',
                        references=['OWASP SC-03:2026', 'MakinaFi $1.3M'], source='regex',
                    ))

    def _check_flash_loan_exposure(self, code, contract, findings):
        for p in [r'function\s+onFlashLoan\s*\(', r'function\s+receiveFlashLoan\s*\(', r'IFlashLoanReceiver']:
            if re.search(p, code):
                findings.append(Finding(
                    vuln_id='FLASH-RX01', category='Flash Loan Exposure', severity='MEDIUM',
                    title='Flash loan receiver detected',
                    description='Accepts flash loans. Any callback vuln becomes zero-cap exploitable.',
                    location=contract, confidence=0.95, zero_capital=True, flash_loan_required=True, source='regex',
                ))
                return

    def _check_delegatecall(self, code, contract, findings):
        if re.search(r'delegatecall\s*\([^)]*(?:addr|target|impl|_to)\)', code, re.I):
            findings.append(Finding(
                vuln_id='DELG-RX01', category='Unsafe Delegatecall', severity='CRITICAL',
                title='delegatecall to variable address',
                description='delegatecall to non-constant = arbitrary code execution.',
                location=contract, confidence=0.7, zero_capital=True,
                attack_scenario='Set delegatecall target to malicious contract.',
                source='regex',
            ))

    def _check_initialization(self, code, contract, findings):
        has_proxy = bool(re.search(r'implementation\s*=|_IMPLEMENTATION_SLOT|proxy', code, re.I))
        has_init = bool(re.search(r'function\s+initialize\s*\(', code))
        has_guard = bool(re.search(r'_initialized|initializer|!initialized|Initializable', code))
        if has_proxy and has_init and not has_guard:
            findings.append(Finding(
                vuln_id='INIT-RX01', category='Initialization', severity='CRITICAL',
                title='Unprotected initialize() in proxy',
                description='Proxy with initialize() but no re-init guard. Attacker can call initialize() to take over.',
                location=f'{contract}:initialize()', confidence=0.8, zero_capital=True,
                attack_scenario='Call initialize with attacker as owner.',
                remediation='Use OpenZeppelin Initializable.', source='regex',
            ))

    def _check_selfdestruct(self, code, contract, findings):
        for m in re.finditer(r'selfdestruct\s*\(', code):
            ctx = code[max(0, m.start()-200):m.end()]
            if not re.search(r'onlyOwner|onlyAdmin|onlyRole', ctx):
                findings.append(Finding(
                    vuln_id='SELF-RX01', category='Selfdestruct', severity='CRITICAL',
                    title='Unprotected selfdestruct', description='Anyone can destroy contract.',
                    location=f'{contract}:{m.start()}', confidence=0.9, zero_capital=True, source='regex',
                ))

    def _check_erc20_safety(self, code, contract, findings):
        if re.search(r'SafeERC20|safeTransfer|safeTransferFrom', code):
            return
        for pattern, desc in [(r'\b\w+\.transfer\s*\([^)]+\)\s*;', 'transfer'),
                              (r'\b\w+\.transferFrom\s*\([^)]+\)\s*;', 'transferFrom')]:
            for m in re.finditer(pattern, code):
                line_end = code.find(';', m.end())
                line = code[m.start():line_end+1] if line_end != -1 else code[m.start():m.start()+100]
                if 'require' not in line and 'if' not in line and '!=' not in line:
                    findings.append(Finding(
                        vuln_id='ERC20-RX01', category='Unsafe ERC20', severity='MEDIUM',
                        title=f'Unchecked {desc} return', description='Return not checked. USDT/fee-on-transfer will fail silently.',
                        location=f'{contract}:{m.start()}', confidence=0.65, source='regex',
                    ))

    def _check_rounding_errors(self, code, contract, findings):
        for pattern, desc in [(r'\*\s*1e18\s*\/\s*\w+', 'multiply-then-divide rounding')]:
            if re.search(pattern, code, re.I):
                findings.append(Finding(
                    vuln_id='LOGIC-RX01', category='Logic Error', severity='HIGH',
                    title=f'Rounding: {desc}',
                    description=f'Balancer V2 $128M (Nov 2025) rounding exploit pattern.',
                    location=contract, confidence=0.4, flash_loan_required=True, source='regex',
                ))

    def _check_timelock(self, code, contract, findings):
        has_admin = bool(re.search(r'onlyOwner|onlyAdmin', code))
        has_tl = bool(re.search(r'timelock|TimelockController|MINIMUM_DELAY|DELAY', code, re.I))
        if has_admin and not has_tl:
            findings.append(Finding(
                vuln_id='TL-RX01', category='Missing/Weak Timelock', severity='MEDIUM',
                title='No timelock on admin functions',
                description='Term Finance: 7-day TL zeroed via gov takeover.',
                location=contract, confidence=0.5, references=['Term Finance $8.5M'], source='regex',
            ))

    def _check_governance_patterns(self, code, contract, findings):
        if re.search(r'proposalThreshold\s*=\s*0', code):
            findings.append(Finding(
                vuln_id='GOV-RX01', category='Governance', severity='CRITICAL',
                title='Zero proposal threshold',
                description='Anyone can create proposals. Term Finance $8.5M.',
                location=contract, confidence=0.9, zero_capital=True, source='regex',
            ))
        if re.search(r'proposalThreshold|quorum|votingDelay', code):
            if not re.search(r'timelock|delay.*execute|executionDelay|queue', code, re.I):
                findings.append(Finding(
                    vuln_id='GOV-RX02', category='Governance', severity='HIGH',
                    title='Governance without execution delay',
                    description='Gov actions execute instantly. No reaction time.',
                    location=contract, confidence=0.7, source='regex',
                ))

    def _check_integer_arithmetic(self, code, contract, findings):
        ver_match = re.search(r'pragma\s+solidity\s+(\^?\d+\.\d+\.\d+)', code)
        if ver_match:
            ver = ver_match.group(1)
            major, minor = map(int, ver.lstrip('^').split('.')[:2])
            if major < 8 or (major == 8 and minor == 0):
                findings.append(Finding(
                    vuln_id='INT-RX01', category='Integer Overflow/Underflow', severity='HIGH',
                    title=f'Outdated Solidity: {ver}', description=f'No built-in overflow checks. Upgrade to >= 0.8.8.',
                    location=contract, confidence=0.9, source='regex',
                ))

    def _run_abi_analysis(self, abi_parsed, contract, source):
        findings = []
        dangerous = self.fetcher.get_dangerous_functions(abi_parsed)
        for df in dangerous:
            name = df['name']
            func_pattern = rf'function\s+{re.escape(name)}\s*\('
            m = re.search(func_pattern, source)
            if not m:
                continue
            func_ctx = source[m.start():m.start() + 500]
            has_ac = bool(re.search(r'onlyOwner|onlyAdmin|onlyRole|_checkRole|if\s*\(msg\.sender', func_ctx))
            if not has_ac and not df.get('payable', False):
                crit = {'withdraw', 'withdrawAll', 'sweep', 'mint', 'burn', 'setOwner',
                       'transferOwnership', 'setImplementation', 'upgradeTo', 'selfdestruct', 'setOracle'}
                sev = 'CRITICAL' if name.lower() in crit else 'HIGH'
                findings.append(Finding(
                    vuln_id='ABI-001', category='Access Control', severity=sev,
                    title=f'ABI: Unprotected {name}()',
                    description=f'{name}() is state-changing with no access control.',
                    location=f'{contract}:{name}()', confidence=0.8, zero_capital=True,
                    raw_data={'abi_function': df}, source='abi',
                ))
        return findings

    def _clean_source(self, source):
        cleaned = re.sub(r'//.*$', '', source, flags=re.MULTILINE)
        cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
        return cleaned

    def _deduplicate(self):
        seen = {}
        unique = []
        for f in self.findings:
            key = (f.vuln_id, f.location[:100], f.category)
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        self.findings = list(seen.values())
