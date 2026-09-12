"""
analyzer.py
-----------
Core password analysis logic for the Password Strength Analyzer.

This module contains NO server code and NO storage code. It receives a
password string as a Python variable, analyzes it in memory, and returns
a plain dictionary describing the result. Nothing here ever writes the
password to disk, to a log file, or to any external service.

Security education note:
A "complex" password (one that uses many character types) is not the
same thing as an "unpredictable" password. "Password123!" satisfies
almost every basic character-type rule, but it is still weak because
it is built from a dictionary word, a predictable number sequence, and
a single common special character appended at the end. Attackers'
cracking tools (e.g. dictionary + "mangling rules" attacks) are built
specifically to guess passwords shaped exactly like this.

Long, random passphrases (e.g. "correct horse battery staple" style,
or better, truly random word lists) are often stronger than short
"complex" passwords because length increases the search space
exponentially, while human-chosen complexity patterns are easy for
attackers to predict.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Configuration / Password Policy
# ---------------------------------------------------------------------------

DEFAULT_POLICY = {
    "min_length": 12,
    "recommended_length": 16,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_number": True,
    "require_special": True,
    "max_length": 128,  # sane upper bound to avoid pathological input
}

SPECIAL_CHARS = r"""!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~`"""

_COMMON_PASSWORDS_PATH = Path(__file__).parent / "data" / "common_passwords.txt"


def _load_common_passwords() -> set:
    """Load the local common-password list into memory once.

    We never download this list automatically and we never send any
    password to an external API to check it — everything is local.
    """
    if not _COMMON_PASSWORDS_PATH.exists():
        return set()
    with open(_COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


_COMMON_PASSWORDS = _load_common_passwords()

# A few very common keyboard-walk patterns, checked as substrings.
_KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "qwertyuiop",
    "asdfghjkl", "zxcvbnm",
]

# Common leetspeak substitutions attackers' tools try automatically.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})


def _normalize_for_dictionary_check(password: str) -> str:
    """Undo common leetspeak substitutions and lowercase, for comparison
    against the common-password list. This is intentionally simple —
    it will not catch every variation, and that limitation is documented
    in the README.
    """
    return password.lower().translate(_LEET_MAP)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _has_upper(pw: str) -> bool:
    return bool(re.search(r"[A-Z]", pw))


def _has_lower(pw: str) -> bool:
    return bool(re.search(r"[a-z]", pw))


def _has_number(pw: str) -> bool:
    return bool(re.search(r"[0-9]", pw))


def _has_special(pw: str) -> bool:
    return bool(re.search(f"[{re.escape(SPECIAL_CHARS)}]", pw))


def _character_set_size(pw: str) -> int:
    """Estimate the size of the character 'alphabet' the password draws
    from, based on which categories are present. This is used only for
    the entropy estimate, not for correctness of what characters are in
    the password.
    """
    size = 0
    if _has_lower(pw):
        size += 26
    if _has_upper(pw):
        size += 26
    if _has_number(pw):
        size += 10
    if _has_special(pw):
        size += len(set(SPECIAL_CHARS))
    return size or 1  # avoid log2(0)


def _has_repeated_chars(pw: str, run_length: int = 4) -> bool:
    """Detect a single character repeated `run_length` or more times in a row,
    e.g. 'aaaa'."""
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + r",}", pw))


def _has_sequential_chars(pw: str, run_length: int = 4) -> bool:
    """Detect ascending or descending sequences of letters or digits,
    e.g. '1234', 'abcd', 'dcba'."""
    lowered = pw.lower()
    ascending = "abcdefghijklmnopqrstuvwxyz0123456789"
    descending = ascending[::-1]
    for seq in (ascending, descending):
        for i in range(len(seq) - run_length + 1):
            if seq[i:i + run_length] in lowered:
                return True
    return False


def _has_keyboard_pattern(pw: str) -> bool:
    lowered = pw.lower()
    return any(pattern in lowered for pattern in _KEYBOARD_PATTERNS)


def _is_common_password(pw: str) -> bool:
    lowered = pw.lower()
    normalized = _normalize_for_dictionary_check(pw)
    if lowered in _COMMON_PASSWORDS or normalized in _COMMON_PASSWORDS:
        return True
    # Detect "common word + trailing digits/punctuation" variations,
    # e.g. "password1234" or "qwerty!!" — strip trailing digits/special
    # characters from the ORIGINAL (pre-leet) lowercased password first,
    # then apply the leet-normalization to what's left. This will not
    # catch every variation.
    stripped_raw = re.sub(r"[\d!@#$%^&*_\-]+$", "", lowered)
    stripped_normalized = stripped_raw.translate(_LEET_MAP)
    return (
        stripped_raw != ""
        and (stripped_raw in _COMMON_PASSWORDS or stripped_normalized in _COMMON_PASSWORDS)
    )


# ---------------------------------------------------------------------------
# Entropy estimation
# ---------------------------------------------------------------------------

def estimate_entropy_bits(pw: str) -> float:
    """Rough entropy estimate in bits using: length * log2(alphabet_size).

    IMPORTANT LIMITATION (documented for the user in the UI and README):
    This formula assumes every character was chosen uniformly at random
    from the estimated alphabet. Real human-chosen passwords are NOT
    random, so this number can badly OVERESTIMATE real-world security
    for predictable passwords (e.g. dictionary words, names, patterns).
    Treat this purely as a rough, best-case upper bound, not a
    guarantee of actual strength.
    """
    if not pw:
        return 0.0
    alphabet_size = _character_set_size(pw)
    return round(len(pw) * math.log2(alphabet_size), 1)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _strength_label(score: int) -> str:
    if score <= 20:
        return "Very Weak"
    if score <= 40:
        return "Weak"
    if score <= 60:
        return "Moderate"
    if score <= 80:
        return "Strong"
    return "Very Strong"


def analyze_password(password: str, policy: Dict = None) -> Dict:
    """Analyze a password and return a result dictionary.

    The password is only ever held in a local variable for the duration
    of this function call. It is never written to a file, a log, a
    database, or a network request.
    """
    policy = policy or DEFAULT_POLICY

    if password is None:
        password = ""

    # Basic input safety: cap length to avoid pathological/huge input.
    truncated = False
    if len(password) > policy["max_length"]:
        password = password[: policy["max_length"]]
        truncated = True

    length = len(password)

    checks = {
        "minimum_length": length >= policy["min_length"],
        "recommended_length": length >= policy["recommended_length"],
        "uppercase": _has_upper(password),
        "lowercase": _has_lower(password),
        "number": _has_number(password),
        "special": _has_special(password),
    }

    variety_count = sum([
        checks["uppercase"], checks["lowercase"], checks["number"], checks["special"]
    ])
    checks["good_variety"] = variety_count >= 3

    warnings: List[str] = []
    recommendations: List[str] = []

    if length == 0:
        warnings.append("Password is empty.")
    elif length < policy["min_length"]:
        warnings.append(f"Password is shorter than {policy['min_length']} characters.")
        recommendations.append(f"Use at least {policy['min_length']} characters.")

    if length < policy["recommended_length"] and length >= policy["min_length"]:
        recommendations.append(
            f"Consider {policy['recommended_length']}+ characters for stronger protection."
        )

    if not checks["uppercase"]:
        recommendations.append("Add uppercase letters.")
    if not checks["lowercase"]:
        recommendations.append("Add lowercase letters.")
    if not checks["number"]:
        recommendations.append("Add numbers.")
    if not checks["special"]:
        recommendations.append("Add special characters.")

    is_repeated = _has_repeated_chars(password) if password else False
    is_sequential = _has_sequential_chars(password) if password else False
    is_keyboard = _has_keyboard_pattern(password) if password else False
    is_common = _is_common_password(password) if password else False

    if is_repeated:
        warnings.append("Contains a long run of the same character.")
    if is_sequential:
        warnings.append("Contains a sequential pattern (e.g. 1234, abcd).")
    if is_keyboard:
        warnings.append("Contains a keyboard-walk pattern (e.g. qwerty).")
    if is_common:
        warnings.append("Matches a common/leaked password or an obvious variation of one.")

    if is_repeated or is_sequential or is_keyboard or is_common:
        recommendations.append("Avoid common words, patterns, and predictable substitutions.")

    if length > 0 and variety_count >= 3 and length < policy["recommended_length"]:
        recommendations.append(
            "Consider using a long, random passphrase instead of a short complex password."
        )

    # ---------------- Scoring ----------------
    # The score rewards length heavily (length is the single biggest factor
    # in real-world resistance to brute-force attacks) and character
    # variety moderately, then subtracts for predictable patterns. It is
    # intentionally NOT "one point per character-type box checked" —
    # a password can tick every box and still lose most of its score to
    # pattern/common-password penalties.
    score = 0.0

    # Length component: up to 50 points, scaling toward the recommended length.
    length_ratio = min(length / policy["recommended_length"], 1.5) if length else 0
    score += min(length_ratio * 50, 55)

    # Variety component: up to 25 points.
    score += variety_count * 6.25  # 4 categories max = 25 points

    # Entropy-informed bonus: up to 20 points, based on estimated bits,
    # capped so entropy alone can't fully offset pattern penalties.
    entropy = estimate_entropy_bits(password)
    score += min(entropy / 4, 20)

    # Penalties for predictability.
    if is_common:
        score -= 45
    if is_keyboard:
        score -= 20
    if is_sequential:
        score -= 15
    if is_repeated:
        score -= 15
    if length < policy["min_length"] and length > 0:
        score -= 10

    score = max(0, min(100, round(score)))
    if length == 0:
        score = 0

    strength = _strength_label(score)

    if strength in ("Strong", "Very Strong") and not recommendations:
        recommendations.append("Great job — keep using a unique password for every account.")

    result = {
        "score": score,
        "strength": strength,
        "length": length,
        "checks": checks,
        "entropy_estimate": entropy,
        "warnings": warnings,
        "recommendations": recommendations,
        "truncated": truncated,
    }
    return result
