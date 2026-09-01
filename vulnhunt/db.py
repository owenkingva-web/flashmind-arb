"""T3-3 Database Layer - SQLite persistence for all scan data, findings, and targets."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import DB_PATH


class Database:
    """SQLite database for tracking protocols, scans, findings, and executions."""

    def __init__(self, path: str = None):
        self.path = Path(path) if path else DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        c = self.conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            tvl REAL DEFAULT 0,
            chains TEXT DEFAULT '[]',
            address TEXT,
            url TEXT,
            listed_at TEXT,
            first_seen TEXT NOT NULL,
            last_scanned TEXT,
            scan_count INTEGER DEFAULT 0,
            is_known_safe INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}'
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            chain_id INTEGER NOT NULL,
            protocol_id INTEGER,
            contract_name TEXT,
            is_proxy INTEGER DEFAULT 0,
            implementation TEXT,
            is_verified INTEGER DEFAULT 0,
            compiler_version TEXT,
            source_fetched_at TEXT,
            bytecode_size INTEGER,
            UNIQUE(address, chain_id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_code TEXT,
            slither_output TEXT,
            regex_findings INTEGER DEFAULT 0,
            slither_findings INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            FOREIGN KEY (contract_id) REFERENCES contracts(id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vuln_id TEXT,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            confidence REAL DEFAULT 0,
            zero_capital INTEGER DEFAULT 0,
            flash_loan_required INTEGER DEFAULT 0,
            estimated_gas INTEGER DEFAULT 0,
            attack_scenario TEXT,
            remediation TEXT,
            raw_data TEXT DEFAULT '{}',
            is_validated INTEGER DEFAULT 0,
            is_exploited INTEGER DEFAULT 0,
            exploit_tx_hash TEXT,
            exploit_profit TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            contract_address TEXT NOT NULL,
            chain_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            tx_hash TEXT,
            gas_used INTEGER,
            gas_cost_eth REAL,
            profit_eth REAL,
            profit_usd REAL,
            success INTEGER DEFAULT 0,
            error TEXT,
            metadata TEXT DEFAULT '{}'
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT,
            protocol_name TEXT,
            contract_address TEXT,
            chain_id INTEGER,
            message TEXT,
            finding_ids TEXT DEFAULT '[]',
            sent INTEGER DEFAULT 0
        )''')

        # Indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_protocols_slug ON protocols(slug)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_protocols_tvl ON protocols(tvl)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_contracts_address ON contracts(address, chain_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_contracts_verified ON contracts(is_verified)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_zero_cap ON findings(zero_capital)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_exploited ON findings(is_exploited)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent)')

        self.conn.commit()

    # ── Protocol CRUD ─────────────────────────────────────────────────────

    def upsert_protocol(self, slug: str, name: str, category: str = '',
                         tvl: float = 0, chains: list = None, address: str = '',
                         url: str = '', listed_at: str = '') -> int:
        c = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        c.execute('''INSERT INTO protocols (slug, name, category, tvl, chains, address, url, listed_at, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
                tvl=excluded.tvl, chains=excluded.chains,
                address=COALESCE(NULLIF(excluded.address, ''), address),
                last_scanned=last_scanned
            RETURNING id
        ''', (slug, name, category, tvl, json.dumps(chains or []),
              address, url, listed_at, now))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    def get_unscanned_protocols(self, hours: int = 24) -> list:
        c = self.conn.cursor()
        cutoff = datetime.now(timezone.utc).isoformat()
        c.execute('''SELECT * FROM protocols
            WHERE (last_scanned IS NULL OR last_scanned < datetime(?, '-24 hours'))
            AND is_known_safe = 0
            ORDER BY tvl DESC
            LIMIT 50
        ''', (cutoff,))
        return [dict(r) for r in c.fetchall()]

    def get_protocols_with_findings(self, severity: str = 'CRITICAL', zero_cap: bool = True) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT p.name, p.slug, p.tvl, p.address, f.title, f.severity, f.confidence,
                  f.zero_capital, f.flash_loan_required, f.location, f.attack_scenario,
                  co.address as contract_address, co.chain_id
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN contracts co ON s.contract_id = co.id
            JOIN protocols p ON co.protocol_id = p.id
            WHERE f.severity = ? AND f.zero_capital = ? AND f.is_exploited = 0
            ORDER BY f.confidence DESC
        ''', (severity, 1 if zero_cap else 0))
        return [dict(r) for r in c.fetchall()]

    # ── Contract CRUD ─────────────────────────────────────────────────────

    def upsert_contract(self, address: str, chain_id: int, protocol_id: int = 0,
                         contract_name: str = '', is_proxy: bool = False,
                         implementation: str = '', is_verified: bool = False,
                         compiler_version: str = '', bytecode_size: int = 0) -> int:
        c = self.conn.cursor()
        c.execute('''INSERT INTO contracts (address, chain_id, protocol_id, contract_name,
                is_proxy, implementation, is_verified, compiler_version, source_fetched_at, bytecode_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address, chain_id) DO UPDATE SET
                contract_name=excluded.contract_name, is_proxy=excluded.is_proxy,
                implementation=excluded.implementation, is_verified=excluded.is_verified,
                compiler_version=excluded.compiler_version,
                source_fetched_at=excluded.source_fetched_at,
                bytecode_size=excluded.bytecode_size
            RETURNING id
        ''', (address, chain_id, protocol_id, contract_name,
              1 if is_proxy else 0, implementation,
              1 if is_verified else 0, compiler_version,
              datetime.now(timezone.utc).isoformat(), bytecode_size))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    def get_protocol_by_slug(self, slug: str) -> Optional[dict]:
        c = self.conn.cursor()
        c.execute('SELECT * FROM protocols WHERE slug = ?', (slug,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_known_proxies(self) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT * FROM contracts WHERE is_proxy = 1 AND implementation IS NOT NULL
                      AND implementation != '' ORDER BY chain_id''')
        return [dict(r) for r in c.fetchall()]

    def get_contract(self, address: str, chain_id: int) -> Optional[dict]:
        c = self.conn.cursor()
        c.execute('SELECT * FROM contracts WHERE address = ? AND chain_id = ?',
                  (address.lower(), chain_id))
        row = c.fetchone()
        return dict(row) if row else None

    def get_verified_unscanned_contracts(self, limit: int = 20) -> list:
        c = self.conn.cursor()
        c.execute('''SELECT co.*, p.name as protocol_name, p.tvl
            FROM contracts co
            LEFT JOIN protocols p ON co.protocol_id = p.id
            WHERE co.is_verified = 1
            AND co.id NOT IN (SELECT DISTINCT contract_id FROM scans WHERE timestamp > datetime('now', '-1 hours'))
            ORDER BY p.tvl DESC NULLS LAST
            LIMIT ?
        ''', (limit,))
        return [dict(r) for r in c.fetchall()]

    def get_contracts_needing_rescan(self, hours: int = 6, limit: int = 100) -> list:
        """Get contracts that were scanned more than N hours ago and need re-scanning."""
        c = self.conn.cursor()
        c.execute('''SELECT co.*, p.name as protocol_name, p.tvl, p.slug,
                  MAX(s.timestamp) as last_scan_time
            FROM contracts co
            LEFT JOIN protocols p ON co.protocol_id = p.id
            LEFT JOIN scans s ON s.contract_id = co.id
            WHERE co.is_verified = 1
            GROUP BY co.id
            HAVING last_scan_time IS NULL OR last_scan_time < datetime('now', ? || ' hours')
            ORDER BY p.tvl DESC NULLS LAST
            LIMIT ?
        ''', (f'-{hours}', limit))
        return [dict(r) for r in c.fetchall()]

    # ── Scan CRUD ─────────────────────────────────────────────────────────

    def create_scan(self, contract_id: int, scan_type: str = 'full',
                    source_code: str = '', slither_output: str = '') -> int:
        c = self.conn.cursor()
        c.execute('''INSERT INTO scans (contract_id, scan_type, timestamp, source_code, slither_output)
            VALUES (?, ?, ?, ?, ?)
            RETURNING id
        ''', (contract_id, scan_type,
              datetime.now(timezone.utc).isoformat(), source_code, slither_output))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    def update_scan_counts(self, scan_id: int, regex_f: int, slither_f: int,
                           critical: int, high: int, medium: int, low: int):
        c = self.conn.cursor()
        total = regex_f + slither_f
        c.execute('''UPDATE scans SET
            regex_findings=?, slither_findings=?, total_findings=?,
            critical_count=?, high_count=?, medium_count=?, low_count=?
            WHERE id=?
        ''', (regex_f, slither_f, total, critical, high, medium, low, scan_id))
        # Also update protocol last_scanned
        c.execute('''UPDATE protocols SET last_scanned = ?, scan_count = scan_count + 1
            WHERE id = (SELECT protocol_id FROM contracts WHERE id = ?)
        ''', (datetime.now(timezone.utc).isoformat(), scan_id))
        self.conn.commit()

    # ── Finding CRUD ──────────────────────────────────────────────────────

    def add_finding(self, scan_id: int, vuln_id: str, category: str, severity: str,
                    title: str, description: str = '', location: str = '',
                    confidence: float = 0, zero_capital: bool = False,
                    flash_loan_required: bool = False, estimated_gas: int = 0,
                    attack_scenario: str = '', remediation: str = '',
                    raw_data: dict = None) -> int:
        c = self.conn.cursor()
        c.execute('''INSERT INTO findings
            (scan_id, vuln_id, category, severity, title, description, location,
             confidence, zero_capital, flash_loan_required, estimated_gas,
             attack_scenario, remediation, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        ''', (scan_id, vuln_id, category, severity, title, description, location,
              confidence, 1 if zero_capital else 0, 1 if flash_loan_required else 0,
              estimated_gas, attack_scenario, remediation,
              json.dumps(raw_data or {})))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    def mark_finding_validated(self, finding_id: int, is_valid: bool):
        c = self.conn.cursor()
        c.execute('UPDATE findings SET is_validated = 1 WHERE id = ? AND is_validated = 0', (finding_id,))
        self.conn.commit()

    def mark_finding_exploited(self, finding_id: int, tx_hash: str, profit_eth: float = 0, profit_usd: float = 0):
        c = self.conn.cursor()
        c.execute('''UPDATE findings SET is_exploited = 1, exploit_tx_hash = ?, exploit_profit = ?
            WHERE id = ?
        ''', (tx_hash, f'{profit_eth:.6f} ETH / ${profit_usd:.2f}', finding_id))
        self.conn.commit()

    def get_exploitable_findings(self, min_confidence: float = 0.5,
                                  min_severity: str = 'HIGH') -> list:
        c = self.conn.cursor()
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        min_order = severity_order.get(min_severity, 1)
        c.execute('''SELECT f.*, s.source_code, co.address as contract_address,
                  co.chain_id, p.name as protocol_name, p.tvl
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN contracts co ON s.contract_id = co.id
            LEFT JOIN protocols p ON co.protocol_id = p.id
            WHERE f.zero_capital = 1
            AND f.is_exploited = 0
            AND f.confidence >= ?
            AND f.severity IN ('CRITICAL', 'HIGH')
            ORDER BY f.confidence DESC
        ''', (min_confidence,))
        results = [dict(r) for r in c.fetchall()]
        results.sort(key=lambda x: severity_order.get(x['severity'], 99))
        return results

    # ── Execution CRUD ────────────────────────────────────────────────────

    def log_execution(self, contract_address: str, chain_id: int, action: str,
                      tx_hash: str = '', gas_used: int = 0, gas_cost_eth: float = 0,
                      profit_eth: float = 0, profit_usd: float = 0,
                      success: bool = False, error: str = '',
                      finding_id: int = 0, metadata: dict = None) -> int:
        c = self.conn.cursor()
        c.execute('''INSERT INTO executions
            (finding_id, contract_address, chain_id, timestamp, action,
             tx_hash, gas_used, gas_cost_eth, profit_eth, profit_usd,
             success, error, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        ''', (finding_id, contract_address.lower(), chain_id,
              datetime.now(timezone.utc).isoformat(), action,
              tx_hash, gas_used, gas_cost_eth, profit_eth, profit_usd,
              1 if success else 0, error, json.dumps(metadata or {})))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    # ── Alert CRUD ────────────────────────────────────────────────────────

    def create_alert(self, alert_type: str, severity: str, message: str,
                     protocol_name: str = '', contract_address: str = '',
                     chain_id: int = 0, finding_ids: list = None) -> int:
        c = self.conn.cursor()
        c.execute('''INSERT INTO alerts (timestamp, alert_type, severity, protocol_name,
                contract_address, chain_id, message, finding_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        ''', (datetime.now(timezone.utc).isoformat(), alert_type, severity,
                  protocol_name, contract_address, chain_id, message,
                  json.dumps(finding_ids or [])))
        row = c.fetchone()
        self.conn.commit()
        return row['id'] if row else 0

    def get_unsent_alerts(self) -> list:
        c = self.conn.cursor()
        c.execute('SELECT * FROM alerts WHERE sent = 0 ORDER BY id')
        return [dict(r) for r in c.fetchall()]

    def mark_alerts_sent(self, alert_ids: list):
        if not alert_ids:
            return
        c = self.conn.cursor()
        placeholders = ','.join('?' * len(alert_ids))
        c.execute(f'UPDATE alerts SET sent = 1 WHERE id IN ({placeholders})', alert_ids)
        self.conn.commit()

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        c = self.conn.cursor()
        stats = {}
        for table, label in [('protocols', 'protocols'), ('contracts', 'contracts'),
                             ('scans', 'scans'), ('findings', 'findings'),
                             ('executions', 'executions')]:
            c.execute(f'SELECT COUNT(*) as cnt FROM {table}')
            stats[label] = c.fetchone()['cnt']

        c.execute('SELECT COUNT(*) as cnt FROM findings WHERE severity = \'CRITICAL\' AND is_exploited = 0')
        stats['unexploited_critical'] = c.fetchone()['cnt']

        c.execute('SELECT COUNT(*) as cnt FROM findings WHERE zero_capital = 1 AND is_exploited = 0')
        stats['zero_cap_unexploited'] = c.fetchone()['cnt']

        c.execute('SELECT SUM(CASE WHEN success = 1 THEN profit_usd ELSE 0 END) as total FROM executions')
        row = c.fetchone()
        stats['total_profit_usd'] = row['total'] or 0

        return stats

    def close(self):
        self.conn.close()
