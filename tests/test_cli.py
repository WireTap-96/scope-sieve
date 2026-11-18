import datetime as dt
import unittest
from scopesieve.cli import review, valid_asset

class ScopeSieveTests(unittest.TestCase):
    def setUp(self):
        self.row = {"asset":"app.example.test", "owner":"Security team", "environment":"lab", "authorization_reference":"LAB-001", "authorized_until":"2026-12-31", "last_reviewed":"2026-11-01"}
        self.today = dt.date(2026, 11, 18)

    def test_valid_inventory(self):
        result = review([self.row], as_of=self.today)
        self.assertEqual(result["status"], "ready-for-human-review")
        self.assertEqual(result["errors"], 0)

    def test_expired_authorization_is_error(self):
        row = dict(self.row, authorized_until="2026-11-17")
        result = review([row], as_of=self.today)
        self.assertIn("authorization_expired", [f["code"] for f in result["findings"]])

    def test_duplicate_hosts_are_detected_case_insensitively(self):
        result = review([self.row, dict(self.row, asset="APP.EXAMPLE.TEST")], as_of=self.today)
        self.assertIn("duplicate_asset", [f["code"] for f in result["findings"]])

    def test_rejects_wildcards_and_urls(self):
        self.assertFalse(valid_asset("*.example.test"))
        self.assertFalse(valid_asset("https://example.test"))
        self.assertTrue(valid_asset("192.0.2.10"))

if __name__ == "__main__":
    unittest.main()
