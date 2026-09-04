"""T3-3 Vulnerability Hunter - Unified CLI"""
import argparse
import json
import sys
import os
from datetime import datetime, timezone
from .config import CHAINS, DATA_DIR
from .db import Database
from .discovery import DiscoveryEngine
from .fetcher import SourceFetcher
from .analyzer import VulnerabilityAnalyzer
from .prober import OnChainProber
from .assessor import ExploitabilityAssessor
from .executor import ExploitExecutor
from .alerts import AlertManager
from .agent import HunterAgent

def cmd_discover(args):
    """Discover new DeFi protocols."""
    db = Database()
    engine = DiscoveryEngine(db)
    targets = engine.run_full_discovery(
        chain_ids=[args.chain] if args.chain else None,
        min_tvl=args.min_tvl,
        max_tvl=args.max_tvl,
        days_old=args.days,
    )
    if not targets:
        print('No targets found.')
        return
    print(f'\n{"="*80}')
    print(f'{"PROTOCOL":<25} {"ADDRESS":<44} {"CHAIN":<12} {"PRIORITY":>8} {"SOURCE":<20}')
    print(f'{"="*80}')
    for t in targets[:50]:
        chain = CHAINS.get(t.chain_id, {})
        print(f'{t.name[:24]:<25} {t.address:<44} {chain.get("name", "?"):<12} {t.priority:>8} {t.source:<20}')
    # Save
    out = DATA_DIR / 'discovered_targets.json'
    with open(out, 'w') as f:
        json.dump([{
            'name': t.name, 'address': t.address, 'chain_id': t.chain_id,
            'source': t.source, 'priority': t.priority, 'category': t.category,
        } for t in targets], indent=2)
    print(f'\nSaved {len(targets)} targets to {out}')
    db.close()

def cmd_scan(args):
    """Scan a specific contract for vulnerabilities."""
    db = Database()
    fetcher = SourceFetcher(db)
    analyzer = VulnerabilityAnalyzer(db)
    chain = CHAINS.get(args.chain)
    if not chain:
        print(f'Unsupported chain: {args.chain}')
        return
    print(f'[*] Scanning {args.address} on {chain["name"]}...')
    # Fetch source
    source = fetcher.fetch_source(args.address, args.chain)
    if source:
        print(f'[+] Source: {source["contract_name"]} ({source["compiler_version"]})')
        print(f'    Proxy: {source.get("proxy", "0")}')
        if source.get('implementation'):
            print(f'    Implementation: {source["implementation"]}')
    else:
        print(f'[!] No verified source - running on-chain probe only')
    # Analyze
    findings = analyzer.analyze_contract(args.address, args.chain, source)
    # Probe on-chain
    print(f'\n[*] On-chain probing...')
    prober = OnChainProber(args.chain, db)
    if prober.is_connected():
        probe_data = prober.probe(args.address)
        print(f'    Code size: {probe_data.get("bytecode_size", 0)} bytes')
        print(f'    Balance: {probe_data.get("native_balance", "0")} ETH')
        if probe_data.get('is_proxy'):
            print(f'    PROXY: {probe_data.get("proxy_type")} → {probe_data.get("implementation", "none")}')
        vd = probe_data.get('view_data', {})
        if vd:
            for k, v in vd.items():
                print(f'    {k}: {v}')
    # Assess findings
    assessor = ExploitabilityAssessor()
    print(f'\n{"="*80}')
    print(f'SCAN RESULTS: {args.address} on {chain["name"]}')
    print(f'{"="*80}')
    critical = sum(1 for f in findings if f.severity == 'CRITICAL')
    high = sum(1 for f in findings if f.severity == 'HIGH')
    medium = sum(1 for f in findings if f.severity == 'MEDIUM')
    low = sum(1 for f in findings if f.severity == 'LOW')
    print(f'CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}')
    print(f'Engines: Slither={sum(1 for f in findings if f.source=="slither")}, '
          f'Regex={sum(1 for f in findings if f.source=="regex")}, '
          f'ABI={sum(1 for f in findings if f.source=="abi")}')
    if findings:
        print(f'\n{"-"*80}')
        for i, f in enumerate(findings, 1):
            zc = ' [ZERO-CAP]' if f.zero_capital else ''
            fl = ' [FLASH-LOAN]' if f.flash_loan_required else ''
            src = f' [{f.source.upper()}]' if f.source else ''
            print(f'\n{i}. [{f.severity}]{zc}{fl}{src} {f.title}')
            print(f'   Category: {f.category}')
            print(f'   Location: {f.location}')
            print(f'   Confidence: {f.confidence:.0%}')
            print(f'   {f.description[:300]}')
            assessment = assessor.assess(f.to_dict(), args.chain)
            print(f'   Priority: {assessment["priority_score"]}/100')
            print(f'   Action: {assessment["action_reason"]}')
    else:
        print('\nNo significant findings.')
    # Save
    out = DATA_DIR / f'scan_{args.address}_{args.chain}.json'
    with open(out, 'w') as fp:
        json.dump({
            'address': args.address, 'chain_id': args.chain,
            'findings': [f.to_dict() for f in findings],
        }, fp, indent=2)
    print(f'\nSaved to {out}')
    db.close()

def cmd_watch(args):
    """Start the autonomous 24/7 hunting agent."""
    chain_ids = [args.chain] if args.chain else None
    agent = HunterAgent(
        chain_ids=chain_ids,
        auto_execute=args.execute,
        min_confidence_execute=args.min_confidence,
        min_priority_execute=args.min_priority,
    )
    agent.run(interval=args.interval)

def cmd_status(args):
    """Show database stats and recent findings."""
    db = Database()
    stats = db.get_stats()
    print(f'\n{"="*50}')
    print(f'  T3-3 HUNTER STATUS')
    print(f'{"="*50}')
    for k, v in stats.items():
        print(f'  {k}: {v}')
    # Show recent high-priority findings
    findings = db.get_exploitable_findings(min_confidence=0.4)
    if findings:
        print(f'\n  TOP EXPLOITABLE FINDINGS:')
        for f in findings[:10]:
            print(f'    [{f["severity"]}] {f["title"][:60]}')
            print(f'      Confidence: {f["confidence"]:.0%} | {f["contract_address"]} | {CHAINS.get(f["chain_id"], {}).get("name", "?")}')
    db.close()

def cmd_wallet(args):
    """Show wallet info and balances."""
    executor = ExploitExecutor()
    try:
        addr = executor.get_wallet_address()
        print(f'Wallet: {addr}')
        for cid, chain in CHAINS.items():
            try:
                bal = executor.get_balance(cid)
                status = '✓' if bal > 0.001 else '✗ low'
                print(f'  {chain["name"]:<15} {bal:.6f} ETH  {status}')
            except Exception:
                print(f'  {chain["name"]:<15} connection failed')
    except ValueError as e:
        print(f'Wallet: NOT CONFIGURED ({e})')

def main():
    parser = argparse.ArgumentParser(
        description='T3-3 Vulnerability Hunter v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 -m vulnhunt discover --chain 42161
  python3 -m vulnhunt scan --address 0x... --chain 1
  python3 -m vulnhunt watch --interval 300 --execute
  python3 -m vulnhunt status
  python3 -m vulnhunt wallet
        '''
    )
    sub = parser.add_subparsers(dest='command')
    # discover
    p = sub.add_parser('discover', help='Find new DeFi targets')
    p.add_argument('--chain', type=int, help='Chain ID')
    p.add_argument('--min-tvl', type=float, default=0)
    p.add_argument('--max-tvl', type=float, default=5_000_000)
    p.add_argument('--days', type=int, default=90)
    # scan
    p = sub.add_parser('scan', help='Scan a contract')
    p.add_argument('--address', required=True, help='Contract address')
    p.add_argument('--chain', type=int, required=True, help='Chain ID')
    # watch
    p = sub.add_parser('watch', help='Start 24/7 autonomous hunter')
    p.add_argument('--interval', type=int, default=300, help='Scan interval (seconds)')
    p.add_argument('--chain', type=int, help='Chain ID (default: all)')
    p.add_argument('--execute', action='store_true', help='Auto-execute exploits')
    p.add_argument('--min-confidence', type=float, default=0.7)
    p.add_argument('--min-priority', type=int, default=70)
    # status
    sub.add_parser('status', help='Show stats and findings')
    # wallet
    sub.add_parser('wallet', help='Show wallet balances')
    args = parser.parse_args()
    if args.command == 'discover':
        cmd_discover(args)
    elif args.command == 'scan':
        cmd_scan(args)
    elif args.command == 'watch':
        cmd_watch(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'wallet':
        cmd_wallet(args)
    else:
        parser.print_help()
if __name__ == '__main__':
    main()
