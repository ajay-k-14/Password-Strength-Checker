"""
generator.py
------------
Secure password generation.

Security note: this module uses Python's `secrets` module, NOT the
`random` module. `random` is a pseudo-random number generator intended
for simulations/games and is NOT safe for security purposes because its
internal state can sometimes be predicted or reconstructed. `secrets`
is built on the operating system's cryptographically secure random
number source and is the correct tool for generating passwords, tokens,
and keys.

Generated passwords are returned directly to the caller and are never
written to disk, logged, or stored anywhere on the server.
"""

from __future__ import annotations

import secrets
import string
from typing import Dict

MIN_GENERATED_LENGTH = 8
MAX_GENERATED_LENGTH = 128
DEFAULT_GENERATED_LENGTH = 16


class PasswordGenerationError(ValueError):
    """Raised when the generator is given an invalid configuration."""


def generate_password(
    length: int = DEFAULT_GENERATED_LENGTH,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_numbers: bool = True,
    use_special: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Raises PasswordGenerationError if the configuration is invalid
    (e.g. length out of range, or no character sets selected).
    """
    if not isinstance(length, int):
        raise PasswordGenerationError("Length must be an integer.")

    if length < MIN_GENERATED_LENGTH or length > MAX_GENERATED_LENGTH:
        raise PasswordGenerationError(
            f"Length must be between {MIN_GENERATED_LENGTH} and {MAX_GENERATED_LENGTH}."
        )

    pools = []
    required_chars = []

    if use_lowercase:
        pools.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        pools.append(string.ascii_uppercase)
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        pools.append(string.digits)
        required_chars.append(secrets.choice(string.digits))
    if use_special:
        special_chars = "!@#$%^&*()_+-=[]{};:,.<>/?~"
        pools.append(special_chars)
        required_chars.append(secrets.choice(special_chars))

    if not pools:
        raise PasswordGenerationError(
            "At least one character type must be selected."
        )

    if length < len(required_chars):
        raise PasswordGenerationError(
            "Length is too short to include all selected character types."
        )

    combined_pool = "".join(pools)

    # Fill the remaining length with secure random choices from the
    # combined pool, then add the "at least one of each selected type"
    # characters and shuffle securely so the guaranteed characters aren't
    # always in predictable positions.
    remaining_length = length - len(required_chars)
    random_chars = [secrets.choice(combined_pool) for _ in range(remaining_length)]

    all_chars = required_chars + random_chars
    _secure_shuffle(all_chars)

    return "".join(all_chars)


def _secure_shuffle(items: list) -> None:
    """Shuffle a list in place using `secrets` for cryptographic
    security (Fisher-Yates shuffle). `random.shuffle` is not used here
    for the same reason `random` is avoided elsewhere in this module.
    """
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generation_options_from_dict(data: Dict) -> Dict:
    """Safely extract and validate generator options from a request
    payload, applying sane defaults for any missing fields.
    """
    return {
        "length": int(data.get("length", DEFAULT_GENERATED_LENGTH)),
        "use_uppercase": bool(data.get("use_uppercase", True)),
        "use_lowercase": bool(data.get("use_lowercase", True)),
        "use_numbers": bool(data.get("use_numbers", True)),
        "use_special": bool(data.get("use_special", True)),
    }
