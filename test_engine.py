import hashlib
import os
import sqlite3
import tempfile
import unittest

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from masking.maskers import partial_mask
from masking.scanner import luhn_ok
from seed import seed


def dump_hash(path):
    conn = sqlite3.connect(path)
    h = hashlib.sha256()
    for line in conn.iterdump():
        h.update(line.encode())
    conn.close()
    return h.hexdigest()


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "bank.db")
        seed(cls.db)
        cls.engine = MaskingEngine(
            SQLiteBackend(cls.db),
            catalog_path=os.path.join(cls.tmp, "cat.json"),
            audit_path=os.path.join(cls.tmp, "audit.log"),
            secret="test-secret",
        )
        cls.engine.scan()

    def one(self, role, sql):
        r = self.engine.query(role, sql)
        return dict(zip(r.columns, r.rows[0]))

    def test_scanner_tags(self):
        tags = {t.key: t.tag for t in self.engine.tags}
        self.assertEqual(tags["customers.ssn"], "PII_HIGH")
        self.assertEqual(tags["accounts.card_number"], "PII_HIGH")
        self.assertEqual(tags["accounts.balance"], "FINANCIAL_CONFIDENTIAL")
        self.assertEqual(tags["customers.contact"], "PII_MEDIUM")  # found by content, not name
        self.assertNotIn("transactions.merchant", tags)

    def test_roles(self):
        sql = "SELECT ssn, card_number, balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id WHERE c.customer_id=1"
        admin, support, analyst = (self.one(r, sql) for r in ("admin", "support", "analyst"))
        self.assertEqual(admin["ssn"], "123-45-6789")
        self.assertEqual(support["card_number"], "4111-XXXX-XXXX-1111")
        self.assertEqual(support["ssn"], "XXX-XX-6789")
        self.assertTrue(analyst["ssn"].startswith("h_"))
        self.assertEqual(analyst["balance"], "[REDACTED]")

    def test_hash_is_deterministic(self):
        sql = "SELECT ssn FROM customers WHERE customer_id=1"
        self.assertEqual(self.one("analyst", sql), self.one("analyst", sql))

    def test_alias_and_expression_cannot_bypass(self):
        row = self.one("analyst", "SELECT ssn AS x, balance*2 AS y FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 1")
        self.assertTrue(row["x"].startswith("h_"))
        self.assertEqual(row["y"], "[REDACTED]")

    def test_select_star_and_unknown_role(self):
        self.assertEqual(self.one("analyst", "SELECT * FROM customers WHERE customer_id=1")["email"], "[REDACTED]")
        self.assertEqual(self.one("intern", "SELECT full_name FROM customers LIMIT 1")["full_name"], "[REDACTED]")

    def test_non_pii_and_count_untouched(self):
        self.assertEqual(self.one("analyst", "SELECT COUNT(*) AS n FROM customers")["n"], 40)
        self.assertNotEqual(self.one("analyst", "SELECT merchant FROM transactions LIMIT 1")["merchant"], "[REDACTED]")

    def test_content_fallback(self):
        row = self.one("analyst", "SELECT lower(email) AS e FROM customers LIMIT 1")
        self.assertEqual(row["e"], "[REDACTED]")

    def test_write_and_multi_statement_rejected(self):
        for bad in ["DELETE FROM customers", "SELECT 1; DROP TABLE customers", "PRAGMA table_info(customers)",
                    "ATTACH DATABASE 'x.db' AS x"]:
            with self.assertRaises((QueryRejected, sqlite3.Error)):
                self.engine.query("admin", bad)

    def test_raw_data_unchanged(self):
        before = dump_hash(self.db)
        for role in ("admin", "support", "analyst"):
            self.engine.query(role, "SELECT * FROM customers")
        self.assertEqual(before, dump_hash(self.db))

    def test_helpers(self):
        self.assertTrue(luhn_ok("4111-1111-1111-1111"))
        self.assertFalse(luhn_ok("4111-1111-1111-1112"))
        self.assertEqual(partial_mask("asha@x.com", "email"), "a***@x.com")


if __name__ == "__main__":
    unittest.main()
