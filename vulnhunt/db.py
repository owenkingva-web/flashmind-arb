r"""T3-3 Database Layer — PostgreSQL (Railway) / SQLite (local) dual backend.

If DATABASE_URL is set → connects to PostgreSQL (psycopg2).
Otherwise           → falls back to local SQLite file.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import DB_PATH

try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False


def _now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Dual-backend database: PostgreSQL when DATABASE_URL is set, else SQLite."""

    def __init__(self, path: str = None, database_url: str = None):
        url = database_url or os.getenv('DATABASE_URL', '')
        self.is_pg = bool(url) and HAS_PG

        self._lock = threading.RLock()

        if self.is_pg:
            self.conn = psycopg2.connect(url)
            self.conn.autocommit = True
            self.path = 'PostgreSQL'
            print(f'  [DB] PostgreSQL connected')
        else:
            self.path = str(Path(path) if path else Path(DB_PATH))
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            if url:
                print(f'  [DB] WARNING: DATABASE_URL set but psycopg2 not available, falling back to SQLite')
            else:
                print(f'  [DB] SQLite: {self.path}')

        self._init_tables()

    def _init_tables(self):
        if self.is_pg:
            self._init_pg()
        else:
            self._init_sqlite()

    def _init_sqlite(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT,
            tvl REAL DEFAULT 0, chains TEXT DEFAULT '[]', address TEXT,
            url TEXT, listed_at TEXT, first_seen TEXT NOT NULL,
            last_scanned TEXT, scan_count INTEGER DEFAULT 0,
            is_known_safe INTEGER DEFAULT 0, metadata TEXT DEFAULT '{}'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL, chain_id INTEGER NOT NULL,
            protocol_id INTEGER, contract_name TEXT,
            is_proxy INTEGER DEFAULT 0, implementation TEXT,
            is_verified INTEGER DEFAULT 0, compiler_version TEXT,
            source_fetched_at TEXT, bytecode_size INTEGER,
            UNIQUE(address, chain_id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_id INTEGER NOT NULL, scan_type TEXT NOT NULL,
            timestamp TEXT NOT NULL, source_code TEXT, slither_output TEXT,
            regex_findings INTEGER DEFAULT 0, slither_findings INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0, critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL, vuln_id TEXT, category TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
            location TEXT, confidence REAL DEFAULT 0,
            zero_capital INTEGER DEFAULT 0, flash_loan_required INTEGER DEFAULT 0,
            estimated_gas INTEGER DEFAULT 0, attack_scenario TEXT,
            remediation TEXT, raw_data TEXT DEFAULT '{}',
            is_validated INTEGER DEFAULT 0, is_exploited INTEGER DEFAULT 0,
            exploit_tx_hash TEXT, exploit_profit TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER, contract_address TEXT NOT NULL,
            chain_id INTEGER NOT NULL, timestamp TEXT NOT NULL,
            action TEXT NOT NULL, tx_hash TEXT, gas_used INTEGER,
            gas_cost_eth REAL, profit_eth REAL, profit_usd REAL,
            success INTEGER DEFAULT 0, error TEXT, metadata TEXT DEFAULT '{}'
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
            severity TEXT, protocol_name TEXT, contract_address TEXT,
            chain_id INTEGER, message TEXT, finding_ids TEXT DEFAULT '[]',
            sent INTEGER DEFAULT 0
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_protocols_slug ON protocols(slug)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_contracts_address ON contracts(address, chain_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_zero_cap ON findings(zero_capital)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_findings_exploited ON findings(is_exploited)')
        self.conn.commit()

    def _init_pg(self):
        cur = self.conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS protocols (
            id SERIAL PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT,
            tvl REAL DEFAULT 0, chains TEXT DEFAULT '[]', address TEXT,
            url TEXT, listed_at TEXT, first_seen TEXT NOT NULL,
            last_scanned TEXT, scan_count INTEGER DEFAULT 0,
            is_known_safe INTEGER DEFAULT 0, metadata TEXT DEFAULT '{}'
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS contracts (
            id SERIAL PRIMARY KEY,
            address TEXT NOT NULL, chain_id INTEGER NOT NULL,
            protocol_id INTEGER, contract_name TEXT,
            is_proxy INTEGER DEFAULT 0, implementation TEXT,
            is_verified INTEGER DEFAULT 0, compiler_version TEXT,
            source_fetched_at TEXT, bytecode_size INTEGER,
            UNIQUE(address, chain_id)
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            contract_id INTEGER NOT NULL, scan_type TEXT NOT NULL,
            timestamp TEXT NOT NULL, source_code TEXT, slither_output TEXT,
            regex_findings INTEGER DEFAULT 0, slither_findings INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0, critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER NOT NULL, vuln_id TEXT, category TEXT NOT NULL,
            severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
            location TEXT, confidence REAL DEFAULT 0,
            zero_capital INTEGER DEFAULT 0, flash_loan_required INTEGER DEFAULT 0,
            estimated_gas INTEGER DEFAULT 0, attack_scenario TEXT,
            remediation TEXT, raw_data TEXT DEFAULT '{}',
            is_validated INTEGER DEFAULT 0, is_exploited INTEGER DEFAULT 0,
            exploit_tx_hash TEXT, exploit_profit TEXT
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS executions (
            id SERIAL PRIMARY KEY,
            finding_id INTEGER, contract_address TEXT NOT NULL,
            chain_id INTEGER NOT NULL, timestamp TEXT NOT NULL,
            action TEXT NOT NULL, tx_hash TEXT, gas_used INTEGER,
            gas_cost_eth REAL, profit_eth REAL, profit_usd REAL,
            success INTEGER DEFAULT 0, error TEXT, metadata TEXT DEFAULT '{}'
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            timestamp TEXT NOT NULL, alert_type TEXT NOT NULL,
            severity TEXT, protocol_name TEXT, contract_address TEXT,
            chain_id INTEGER, message TEXT, finding_ids TEXT DEFAULT '[]',
            sent INTEGER DEFAULT 0
        )''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_protocols_slug ON protocols(slug)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_contracts_addr ON contracts(address, chain_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_findings_zc ON findings(zero_capital)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_findings_exp ON findings(is_exploited)')
        cur.close()

    # ── Helpers ────────────────────────────────────────────────────────────

    def _row(self, cur):
        """Fetch one row as dict from either backend."""
        if self.is_pg:
            r = cur.fetchone()
            return dict(r) if r else None
        else:
            r = cur.fetchone()
            return dict(r) if r else None

    def _rows(self, cur):
        if self.is_pg:
            return [dict(r) for r in cur.fetchall()]
        else:
            return [dict(r) for r in cur.fetchall()]

    def _q(self, query, params=()):
        """Execute query, return cursor. Caller must hold _lock for SQLite."""
        if self.is_pg:
            cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = self.conn.cursor()
        cur.execute(query, params)
        return cur

    def _q1(self, query, params=()):
        """Execute + fetchone dict."""
        if not self.is_pg:
            self._lock.acquire()
        try:
            cur = self._q(query, params)
            row = self._row(cur)
            cur.close()
            if not self.is_pg:
                self.conn.commit()
            return row
        finally:
            if not self.is_pg:
                self._lock.release()

    def _qall(self, query, params=()):
        """Execute + fetchall dicts."""
        if not self.is_pg:
            self._lock.acquire()
        try:
            cur = self._q(query, params)
            rows = self._rows(cur)
            cur.close()
            if not self.is_pg:
                self.conn.commit()
            return rows
        finally:
            if not self.is_pg:
                self._lock.release()

    def _returning_id(self, query, params=()):
        """Execute INSERT ... RETURNING id, return the id."""
        if not self.is_pg:
            self._lock.acquire()
        try:
            if self.is_pg:
                cur = self.conn.cursor()
                cur.execute(query, params)
                row = cur.fetchone()
                cur.close()
                return row[0] if row else 0
            else:
                c = self.conn.cursor()
                c.execute(query, params)
                row = c.fetchone()
                c.close()
                self.conn.commit()
                return row['id'] if row else 0
        finally:
            if not self.is_pg:
                self._lock.release()

    def _commit(self):
        """Commit current transaction. Caller must hold _lock for SQLite."""
        if not self.is_pg:
            self.conn.commit()

    @property
    def p(self):
        return '%s' if self.is_pg else '?'

    # ── Protocol CRUD ─────────────────────────────────────────────────────

    def upsert_protocol(self, slug, name, category='', tvl=0,
                         chains=None, address='', url='', listed_at='') -> int:
        now = _now()
        if self.is_pg:
            q = """INSERT INTO protocols (slug, name, category, tvl, chains, address, url, listed_at, first_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (slug) DO UPDATE SET
                    tvl=EXCLUDED.tvl, chains=EXCLUDED.chains,
                    address=COALESCE(NULLIF(EXCLUDED.address, ''), protocols.address),
                    last_scanned=protocols.last_scanned
                RETURNING id"""
        else:
            q = """INSERT INTO protocols (slug, name, category, tvl, chains, address, url, listed_at, first_seen)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(slug) DO UPDATE SET
                    tvl=excluded.tvl, chains=excluded.chains,
                    address=COALESCE(NULLIF(excluded.address, ''), address),
                    last_scanned=last_scanned
                RETURNING id"""
        return self._returning_id(q, (slug, name, category, tvl,
                                     json.dumps(chains or []), address, url, listed_at, now))

    def get_unscanned_protocols(self, hours=24) -> list:
        if self.is_pg:
            return self._qall("""SELECT * FROM protocols
                WHERE (last_scanned IS NULL OR last_scanned < NOW() - INTERVAL '24 hours')
                AND is_known_safe = 0 ORDER BY tvl DESC LIMIT 50""")
        else:
            cutoff = _now()
            return self._qall("""SELECT * FROM protocols
                WHERE (last_scanned IS NULL OR last_scanned < datetime(?, '-24 hours'))
                AND is_known_safe = 0 ORDER BY tvl DESC LIMIT 50""", (cutoff,))

    def get_protocols_with_findings(self, severity='CRITICAL', zero_cap=True) -> list:
        ph = self.p
        q = f"""SELECT p.name, p.slug, p.tvl, p.address, f.title, f.severity, f.confidence,
                  f.zero_capital, f.flash_loan_required, f.location, f.attack_scenario,
                  co.address as contract_address, co.chain_id
            FROM findings f JOIN scans s ON f.scan_id = s.id
            JOIN contracts co ON s.contract_id = co.id
            JOIN protocols p ON co.protocol_id = p.id
            WHERE f.severity = {ph} AND f.zero_capital = {ph} AND f.is_exploited = 0
            ORDER BY f.confidence DESC"""
        return self._qall(q, (severity, 1 if zero_cap else 0))

    # ── Contract CRUD ─────────────────────────────────────────────────────

    def upsert_contract(self, address, chain_id, protocol_id=0,
                         contract_name='', is_proxy=False, implementation='',
                         is_verified=False, compiler_version='', bytecode_size=0) -> int:
        now = _now()
        if self.is_pg:
            q = """INSERT INTO contracts (address, chain_id, protocol_id, contract_name,
                    is_proxy, implementation, is_verified, compiler_version, source_fetched_at, bytecode_size)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (address, chain_id) DO UPDATE SET
                    contract_name=EXCLUDED.contract_name, is_proxy=EXCLUDED.is_proxy,
                    implementation=EXCLUDED.implementation, is_verified=EXCLUDED.is_verified,
                    compiler_version=EXCLUDED.compiler_version,
                    source_fetched_at=EXCLUDED.source_fetched_at, bytecode_size=EXCLUDED.bytecode_size
                RETURNING id"""
        else:
            q = """INSERT INTO contracts (address, chain_id, protocol_id, contract_name,
                    is_proxy, implementation, is_verified, compiler_version, source_fetched_at, bytecode_size)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(address, chain_id) DO UPDATE SET
                    contract_name=excluded.contract_name, is_proxy=excluded.is_proxy,
                    implementation=excluded.implementation, is_verified=excluded.is_verified,
                    compiler_version=excluded.compiler_version,
                    source_fetched_at=excluded.source_fetched_at, bytecode_size=excluded.bytecode_size
                RETURNING id"""
        return self._returning_id(q, (address, chain_id, protocol_id, contract_name,
                                     1 if is_proxy else 0, implementation,
                                     1 if is_verified else 0, compiler_version, now, bytecode_size))

    def get_protocol_by_slug(self, slug) -> Optional[dict]:
        return self._q1(f'SELECT * FROM protocols WHERE slug = {self.p}', (slug,))

    def get_known_proxies(self) -> list:
        return self._qall("""SELECT * FROM contracts WHERE is_proxy = 1
                          AND implementation IS NOT NULL AND implementation != ''
                          ORDER BY chain_id""")

    def get_contract(self, address, chain_id) -> Optional[dict]:
        return self._q1(f'SELECT * FROM contracts WHERE address = {self.p} AND chain_id = {self.p}',
                       (address.lower(), chain_id))

    def get_verified_unscanned_contracts(self, limit=20) -> list:
        ph = self.p
        if self.is_pg:
            q = f"""SELECT co.*, p.name as protocol_name, p.tvl
                FROM contracts co LEFT JOIN protocols p ON co.protocol_id = p.id
                WHERE co.is_verified = 1
                AND co.id NOT IN (SELECT DISTINCT contract_id FROM scans WHERE timestamp > NOW() - INTERVAL '1 hour')
                ORDER BY p.tvl DESC NULLS LAST LIMIT {ph}"""
        else:
            q = f"""SELECT co.*, p.name as protocol_name, p.tvl
                FROM contracts co LEFT JOIN protocols p ON co.protocol_id = p.id
                WHERE co.is_verified = 1
                AND co.id NOT IN (SELECT DISTINCT contract_id FROM scans WHERE timestamp > datetime('now', '-1 hours'))
                ORDER BY p.tvl DESC NULLS LAST LIMIT {ph}"""
        return self._qall(q, (limit,))

    def get_contracts_needing_rescan(self, hours=6, limit=100) -> list:
        ph = self.p
        if self.is_pg:
            q = f"""SELECT co.*, p.name as protocol_name, p.tvl, p.slug,
                      MAX(s.timestamp) as last_scan_time
                FROM contracts co LEFT JOIN protocols p ON co.protocol_id = p.id
                LEFT JOIN scans s ON s.contract_id = co.id
                WHERE co.is_verified = 1
                GROUP BY co.id, p.id
                HAVING last_scan_time IS NULL OR last_scan_time < NOW() - INTERVAL '{hours} hours'
                ORDER BY p.tvl DESC NULLS LAST LIMIT {ph}"""
            return self._qall(q, (limit,))
        else:
            q = f"""SELECT co.*, p.name as protocol_name, p.tvl, p.slug,
                      MAX(s.timestamp) as last_scan_time
                FROM contracts co LEFT JOIN protocols p ON co.protocol_id = p.id
                LEFT JOIN scans s ON s.contract_id = co.id
                WHERE co.is_verified = 1
                GROUP BY co.id
                HAVING last_scan_time IS NULL OR last_scan_time < datetime('now', {ph})
                ORDER BY p.tvl DESC NULLS LAST LIMIT {ph}"""
            return self._qall(q, (f'-{hours}', limit))

    # ── Scan CRUD ─────────────────────────────────────────────────────────

    def create_scan(self, contract_id, scan_type='full', source_code='', slither_output='') -> int:
        ph = self.p
        if self.is_pg:
            q = f"""INSERT INTO scans (contract_id, scan_type, timestamp, source_code, slither_output)
                VALUES ({ph},{ph},{ph},{ph},{ph}) RETURNING id"""
        else:
            q = f"""INSERT INTO scans (contract_id, scan_type, timestamp, source_code, slither_output)
                VALUES (?,?,?,?,?) RETURNING id"""
        return self._returning_id(q, (contract_id, scan_type, _now(), source_code, slither_output))

    def update_scan_counts(self, scan_id, regex_f, slither_f, critical, high, medium, low):
        ph = self.p
        total = regex_f + slither_f
        now = _now()
        if not self.is_pg:
            self._lock.acquire()
        try:
            self._q(f"""UPDATE scans SET
                regex_findings={ph}, slither_findings={ph}, total_findings={ph},
                critical_count={ph}, high_count={ph}, medium_count={ph}, low_count={ph}
                WHERE id={ph}""", (regex_f, slither_f, total, critical, high, medium, low, scan_id))
            self._q(f"""UPDATE protocols SET last_scanned = {ph}, scan_count = scan_count + 1
                WHERE id = (SELECT protocol_id FROM contracts WHERE id = {ph})""", (now, scan_id))
            self._commit()
        finally:
            if not self.is_pg:
                self._lock.release()

    # ── Finding CRUD ──────────────────────────────────────────────────────

    def add_finding(self, scan_id, vuln_id, category, severity, title,
                    description='', location='', confidence=0,
                    zero_capital=False, flash_loan_required=False,
                    estimated_gas=0, attack_scenario='', remediation='',
                    raw_data=None) -> int:
        ph = self.p
        if self.is_pg:
            q = f"""INSERT INTO findings
                (scan_id, vuln_id, category, severity, title, description, location,
                 confidence, zero_capital, flash_loan_required, estimated_gas,
                 attack_scenario, remediation, raw_data)
                VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                RETURNING id"""
        else:
            q = f"""INSERT INTO findings
                (scan_id, vuln_id, category, severity, title, description, location,
                 confidence, zero_capital, flash_loan_required, estimated_gas,
                 attack_scenario, remediation, raw_data)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                RETURNING id"""
        return self._returning_id(q, (scan_id, vuln_id, category, severity, title,
                                     description, location, confidence,
                                     1 if zero_capital else 0,
                                     1 if flash_loan_required else 0,
                                     estimated_gas, attack_scenario, remediation,
                                     json.dumps(raw_data or {})))

    def mark_finding_validated(self, finding_id, is_valid):
        if not self.is_pg:
            self._lock.acquire()
        try:
            self._q(f'UPDATE findings SET is_validated = 1 WHERE id = {self.p} AND is_validated = 0',
                    (finding_id,))
            self._commit()
        finally:
            if not self.is_pg:
                self._lock.release()

    def mark_finding_exploited(self, finding_id, tx_hash, profit_eth=0, profit_usd=0):
        ph = self.p
        profit_str = f'{profit_eth:.6f} ETH / ${profit_usd:.2f}'
        if not self.is_pg:
            self._lock.acquire()
        try:
            self._q(f'UPDATE findings SET is_exploited = 1, exploit_tx_hash = {ph}, exploit_profit = {ph} WHERE id = {ph}',
                    (tx_hash, profit_str, finding_id))
            self._commit()
        finally:
            if not self.is_pg:
                self._lock.release()

    def get_exploitable_findings(self, min_confidence=0.5, min_severity='HIGH') -> list:
        ph = self.p
        q = f"""SELECT f.*, s.source_code, co.address as contract_address,
                  co.chain_id, p.name as protocol_name, p.tvl
            FROM findings f JOIN scans s ON f.scan_id = s.id
            JOIN contracts co ON s.contract_id = co.id
            LEFT JOIN protocols p ON co.protocol_id = p.id
            WHERE f.zero_capital = 1 AND f.is_exploited = 0 AND f.confidence >= {ph}
            AND f.severity IN ('CRITICAL', 'HIGH')
            ORDER BY f.confidence DESC"""
        results = self._qall(q, (min_confidence,))
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        results.sort(key=lambda x: sev_order.get(x['severity'], 99))
        return results

    # ── Execution CRUD ────────────────────────────────────────────────────

    def log_execution(self, contract_address, chain_id, action,
                      tx_hash='', gas_used=0, gas_cost_eth=0,
                      profit_eth=0, profit_usd=0,
                      success=False, error='',
                      finding_id=0, metadata=None) -> int:
        ph = self.p
        if self.is_pg:
            q = f"""INSERT INTO executions
                (finding_id, contract_address, chain_id, timestamp, action,
                 tx_hash, gas_used, gas_cost_eth, profit_eth, profit_usd,
                 success, error, metadata)
                VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                RETURNING id"""
        else:
            q = f"""INSERT INTO executions
                (finding_id, contract_address, chain_id, timestamp, action,
                 tx_hash, gas_used, gas_cost_eth, profit_eth, profit_usd,
                 success, error, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                RETURNING id"""
        return self._returning_id(q, (finding_id, contract_address.lower(), chain_id,
                                     _now(), action, tx_hash, gas_used, gas_cost_eth,
                                     profit_eth, profit_usd, 1 if success else 0, error,
                                     json.dumps(metadata or {})))

    # ── Alert CRUD ────────────────────────────────────────────────────────

    def create_alert(self, alert_type, severity, message,
                     protocol_name='', contract_address='',
                     chain_id=0, finding_ids=None) -> int:
        ph = self.p
        if self.is_pg:
            q = f"""INSERT INTO alerts (timestamp, alert_type, severity, protocol_name,
                    contract_address, chain_id, message, finding_ids)
                VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}) RETURNING id"""
        else:
            q = f"""INSERT INTO alerts (timestamp, alert_type, severity, protocol_name,
                    contract_address, chain_id, message, finding_ids)
                VALUES (?,?,?,?,?,?,?,?) RETURNING id"""
        return self._returning_id(q, (_now(), alert_type, severity, protocol_name,
                                     contract_address, chain_id, message,
                                     json.dumps(finding_ids or [])))

    def get_unsent_alerts(self) -> list:
        return self._qall('SELECT * FROM alerts WHERE sent = 0 ORDER BY id')

    def mark_alerts_sent(self, alert_ids):
        if not alert_ids:
            return
        ph = self.p
        placeholders = ','.join([ph] * len(alert_ids))
        if not self.is_pg:
            self._lock.acquire()
        try:
            self._q(f'UPDATE alerts SET sent = 1 WHERE id IN ({placeholders})', alert_ids)
            self._commit()
        finally:
            if not self.is_pg:
                self._lock.release()

    # ── Stats ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        stats = {}
        for table, label in [('protocols', 'protocols'), ('contracts', 'contracts'),
                             ('scans', 'scans'), ('findings', 'findings'),
                             ('executions', 'executions')]:
            row = self._q1(f'SELECT COUNT(*) as cnt FROM {table}')
            stats[label] = row['cnt'] if row else 0

        row = self._q1("""SELECT COUNT(*) as cnt FROM findings
                         WHERE severity = 'CRITICAL' AND is_exploited = 0""")
        stats['unexploited_critical'] = row['cnt'] if row else 0

        row = self._q1('SELECT COUNT(*) as cnt FROM findings WHERE zero_capital = 1 AND is_exploited = 0')
        stats['zero_cap_unexploited'] = row['cnt'] if row else 0

        row = self._q1('SELECT SUM(CASE WHEN success = 1 THEN profit_usd ELSE 0 END) as total FROM executions')
        stats['total_profit_usd'] = row['total'] if row and row.get('total') else 0

        return stats

    def close(self):
        self.conn.close()
