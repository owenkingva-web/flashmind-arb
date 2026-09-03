import unittest
import os
import tempfile
from unittest.mock import MagicMock

from vulnhunt.db import Database
from vulnhunt.fast_scanner import FastScanner, FastScanResult
from vulnhunt.analyzer import Finding

class TestVulnHunt(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_vulnhunt.db")
        self.db = Database(path=self.db_path)

    def tearDown(self):
        self.db.close()
        self.tmp_dir.cleanup()

    def test_database_crud_and_rescan(self):
        # Test protocol & contract upsert
        p_id = self.db.upsert_protocol("test-protocol", "Test Protocol", tvl=100000)
        c_id = self.db.upsert_contract("0x1234567890123456789012345678901234567890", 42161, protocol_id=p_id, is_verified=True)

        self.assertGreater(p_id, 0)
        self.assertGreater(c_id, 0)

        # Retrieve contracts needing rescan
        rescan = self.db.get_contracts_needing_rescan(hours=1, limit=10)
        self.assertEqual(len(rescan), 1)
        self.assertEqual(rescan[0]["address"], "0x1234567890123456789012345678901234567890")

        # Create scan to update timestamp
        scan_id = self.db.create_scan(c_id, scan_type="test")
        self.assertGreater(scan_id, 0)

    def test_fast_scanner_finding_classification(self):
        scanner = FastScanner(chain_ids=[42161], db=self.db)
        scan_res = FastScanResult(
            address="0x1111111111111111111111111111111111111111",
            chain_id=42161,
            is_proxy=True,
            impl_is_zero=True,
            balance_eth=5.0,
            balance_usd=12000.0,
        )

        findings = scanner._classify_findings(scan_res)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_id, "FAST-UNINIT-001")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertTrue(findings[0].zero_capital)

    def test_signed_transaction_attribute_fallback(self):
        class MockSignedTx:
            def __init__(self, raw_tx):
                self.rawTransaction = raw_tx

        signed = MockSignedTx(b"raw_bytes_data")
        raw = getattr(signed, 'raw_transaction', getattr(signed, 'rawTransaction', None))
        self.assertEqual(raw, b"raw_bytes_data")

if __name__ == "__main__":
    unittest.main()
