"""
Unit tests for generator.py.

Run with:
    pytest tests/test_generator.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from generator import generate_password, PasswordGenerationError  # noqa: E402


class TestPasswordGenerator(unittest.TestCase):

    def test_default_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        pw = generate_password(length=24)
        self.assertEqual(len(pw), 24)

    def test_contains_all_selected_types(self):
        pw = generate_password(
            length=20,
            use_uppercase=True,
            use_lowercase=True,
            use_numbers=True,
            use_special=True,
        )
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(not c.isalnum() for c in pw))

    def test_only_lowercase(self):
        pw = generate_password(
            length=12,
            use_uppercase=False,
            use_lowercase=True,
            use_numbers=False,
            use_special=False,
        )
        self.assertTrue(all(c.islower() for c in pw))

    def test_length_too_short_raises(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(length=4)

    def test_length_too_long_raises(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(length=1000)

    def test_no_character_types_raises(self):
        with self.assertRaises(PasswordGenerationError):
            generate_password(
                use_uppercase=False,
                use_lowercase=False,
                use_numbers=False,
                use_special=False,
            )

    def test_randomness_across_calls(self):
        passwords = {generate_password() for _ in range(10)}
        # Extremely unlikely to collide if using a secure RNG.
        self.assertEqual(len(passwords), 10)


if __name__ == "__main__":
    unittest.main()
