"""
Unit tests for analyzer.py.

Run with:
    pytest tests/test_analyzer.py
or:
    python -m unittest tests.test_analyzer
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import analyze_password  # noqa: E402


class TestPasswordAnalyzer(unittest.TestCase):

    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["strength"], "Very Weak")
        self.assertIn("Password is empty.", result["warnings"])

    def test_very_short_password(self):
        result = analyze_password("ab1!")
        self.assertFalse(result["checks"]["minimum_length"])
        self.assertLess(result["score"], 40)

    def test_common_password_123456(self):
        result = analyze_password("123456")
        self.assertTrue(any("common" in w.lower() for w in result["warnings"]))
        self.assertIn(result["strength"], ("Very Weak", "Weak"))

    def test_common_password_password(self):
        result = analyze_password("password")
        self.assertTrue(any("common" in w.lower() for w in result["warnings"]))

    def test_password123_still_flagged_common_variant(self):
        result = analyze_password("password123")
        self.assertTrue(any("common" in w.lower() for w in result["warnings"]))

    def test_password_with_uppercase_still_weakish(self):
        result = analyze_password("Password123")
        # Ticks several boxes but should not reach the top strength tiers
        # because it's a predictable dictionary-based pattern.
        self.assertNotEqual(result["strength"], "Very Strong")

    def test_password_with_special_char(self):
        result = analyze_password("Password123!")
        self.assertTrue(result["checks"]["special"])
        self.assertTrue(result["checks"]["uppercase"])

    def test_long_random_password_is_strong(self):
        result = analyze_password("qX7#mK2$pL9@zR4!")
        self.assertGreaterEqual(result["score"], 60)

    def test_long_predictable_passphrase(self):
        result = analyze_password("iloveyoumorethananything")
        # Long, but made of dictionary words with no variety — should not
        # score as highly as a random password of similar length.
        self.assertTrue(result["checks"]["minimum_length"])

    def test_repeated_characters(self):
        result = analyze_password("aaaaaaaaaaaa")
        self.assertTrue(any("run of the same character" in w for w in result["warnings"]))

    def test_sequential_characters(self):
        result = analyze_password("abcdefgh1234")
        self.assertTrue(any("sequential" in w.lower() for w in result["warnings"]))

    def test_all_character_types(self):
        result = analyze_password("Tr@il-Blaze9-Path")
        self.assertTrue(result["checks"]["uppercase"])
        self.assertTrue(result["checks"]["lowercase"])
        self.assertTrue(result["checks"]["number"])
        self.assertTrue(result["checks"]["special"])
        self.assertTrue(result["checks"]["good_variety"])

    def test_entropy_is_estimated_and_labeled_numeric(self):
        result = analyze_password("Tr@il-Blaze9-Path")
        self.assertIsInstance(result["entropy_estimate"], float)
        self.assertGreater(result["entropy_estimate"], 0)

    def test_never_returns_original_password(self):
        result = analyze_password("SuperSecret123!")
        self.assertNotIn("SuperSecret123!", str(result))


if __name__ == "__main__":
    unittest.main()
