# Password Strength Analyzer

A beginner-friendly, full-stack web application that analyzes password
strength and teaches core password-security concepts along the way.
Built with **Python/Flask** on the backend and **HTML/CSS/vanilla
JavaScript** on the frontend.

---

## 1. Project Overview

This project lets a user type a password into a web page and instantly
see how strong it is, why it got that rating, and how to improve it.
It also includes a secure random password generator. It is designed
as a learning project for beginners in Python and cybersecurity — the
code favors clarity over cleverness, and every non-obvious security
decision is explained either in code comments or in this README.

## 2. Problem Statement

Many people still choose passwords that are technically "complex"
(they mix uppercase, lowercase, numbers, and symbols) but are still
easy to guess, because they are based on dictionary words, names, or
predictable patterns (`Password123!`, `Summer2024!`). This project
demonstrates how to evaluate passwords in a way that accounts for
*predictability*, not just character-type variety.

## 3. Objectives

- Teach the difference between a "complex" password and an
  "unpredictable" password.
- Demonstrate secure coding practices: no password logging, no
  password storage, cryptographically secure random generation.
- Provide a working, self-contained reference implementation that a
  beginner can read start-to-finish.

## 4. Features

- Real-time password strength analysis (client-side, in the browser)
- Numerical score (0–100) and 5-level strength rating
- Individual pass/fail checks (length, uppercase, lowercase, number,
  special character, overall variety)
- Estimated password entropy, clearly labeled as an estimate
- Local common/weak password detection (no external API calls)
- Pattern detection: repeated characters, sequential characters,
  keyboard-walk patterns, common leetspeak substitutions
- Secure password generator using Python's `secrets` module
- Show/hide password toggle
- Copy-to-clipboard for generated passwords
- Dark, responsive UI

## 5. Technologies Used

- **Backend:** Python 3, Flask
- **Frontend:** HTML5, CSS3, vanilla JavaScript (no frameworks)
- **Standard library modules:** `re`, `math`, `secrets`, `string`,
  `pathlib`
- **Testing:** `pytest` / `unittest`

## 6. Project Architecture

```
Browser (script.js)
   │  real-time analysis happens HERE, locally, on every keystroke
   │
   │  only used for the generator, and optionally for server-side
   │  analysis via an explicit action (not on every keystroke)
   ▼
Flask app (app.py)
   │
   ├── analyzer.py   → strength analysis, entropy, pattern & common-
   │                    password detection, scoring
   └── generator.py  → cryptographically secure password generation
```

The **frontend performs the real-time analysis itself** using a
JavaScript port of the same logic found in `analyzer.py`. This means
the password the user is typing is never sent to the server as they
type. The `/api/analyze` endpoint exists for completeness (e.g. so the
same logic can be tested or used by non-JS clients), but the shipped
UI does not call it on every keystroke.

## 7. Folder Structure

```
password-strength-analyzer/
│
├── app.py
├── analyzer.py
├── generator.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
│   └── common_passwords.txt
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
└── tests/
    ├── test_analyzer.py
    └── test_generator.py
```

## 8. How Password Strength Is Calculated

The score is **not** "one point per character type used." It is built
from three ingredients:

1. **Length** (up to ~55 points) — the single biggest factor in
   real-world resistance to brute-force attacks. Score scales toward
   the recommended length of 16 characters.
2. **Character variety** (up to 25 points) — 6.25 points per category
   present (uppercase, lowercase, number, special), out of 4
   categories.
3. **Entropy-informed bonus** (up to 20 points) — derived from the
   entropy estimate below, capped so it can't fully offset pattern
   penalties.

Then **penalties** are subtracted for predictability:

| Issue                                   | Penalty |
|------------------------------------------|---------|
| Matches a common/leaked password         | −45     |
| Keyboard-walk pattern (e.g. `qwerty`)     | −20     |
| Sequential characters (e.g. `1234`)       | −15     |
| Repeated characters (e.g. `aaaa`)         | −15     |
| Below minimum length                      | −10     |

The final score is clamped to 0–100 and mapped to a strength label:

| Score  | Strength     |
|--------|--------------|
| 0–20   | Very Weak    |
| 21–40  | Weak         |
| 41–60  | Moderate     |
| 61–80  | Strong       |
| 81–100 | Very Strong  |

This is why `Password123!` scores as **Weak**, not Strong — it ticks
every character-type box, but it is a dictionary word with a
predictable number/symbol suffix, so it triggers the "common password
variation" penalty.

## 9. Entropy Explanation

Entropy is estimated using the classic formula:

```
entropy_bits = length × log2(character_set_size)
```

`character_set_size` is estimated from which character categories are
actually present in the password (26 for lowercase, 26 for uppercase,
10 for digits, ~27 for the special-character set used here).

**This is clearly labeled as an ESTIMATE in the UI**, because this
formula assumes every character was chosen *uniformly at random* from
that alphabet. Real human-chosen passwords are not random — a
dictionary word made of only lowercase letters can have a
mathematically "high enough" entropy score by this formula while still
being trivially guessable with a dictionary attack. Entropy estimates
based only on character classes can therefore **overestimate**
real-world security for predictable passwords. That is exactly why
this project also does separate common-password and pattern detection
rather than relying on entropy alone.

## 10. Common Password Detection

`data/common_passwords.txt` contains a local, offline sample of common
and previously-leaked passwords (e.g. `password`, `123456`, `qwerty`,
`iloveyou`). The analyzer:

- Lowercases the password and checks it directly against the list.
- Applies a simple leetspeak-reversal (`0→o`, `1→l`, `3→e`, `4→a`,
  `5→s`, `7→t`, `@→a`, `$→s`) and checks again, to catch things like
  `p@ssw0rd`.
- Strips a trailing run of digits/punctuation (e.g. the `123!` in
  `password123!`) and checks what's left, to catch "common word +
  suffix" variations.

**No password is ever sent to an external API or downloaded list** —
everything is checked against the local file only. This detection is
intentionally simple and will **not** catch every possible variation;
see Limitations below.

## 11. Pattern Detection

The analyzer also looks for:

- **Repeated characters** — the same character 4+ times in a row
  (`aaaaaaaa`).
- **Sequential characters** — 4+ characters in ascending or descending
  order (`1234`, `abcd`, `dcba`).
- **Keyboard-walk patterns** — substrings like `qwerty`, `asdf`,
  `zxcvbnm`, `qazwsx`.

These checks catch obvious, common patterns; they do not attempt to
detect every possible weak pattern.

## 12. Password Generation

The generator (`generator.py`) uses Python's **`secrets`** module —
not `random` — because `secrets` is built on the operating system's
cryptographically secure random source. `random` is a fast,
deterministic pseudo-random generator meant for simulations and games,
and its internal state is not safe to use for anything
security-related (an attacker who can observe enough output can, in
some cases, predict future values).

The generator:

- Lets the user choose length (8–64 in the UI) and which character
  types to include.
- Guarantees at least one character from each selected type.
- Fills the rest of the password with secure random choices from the
  combined pool.
- Shuffles the final character list using a `secrets`-based
  Fisher-Yates shuffle (not `random.shuffle`).
- Is **never stored server-side** — it's generated, returned once in
  the API response, and shown only in the browser.

## 13. Security Considerations

- **No password logging.** No password ever passes through
  `app.logger`, `print()`, or any other logging call.
- **No password persistence.** Passwords exist only as local variables
  during a single request/response cycle (or a single keystroke event
  in the browser) and are discarded immediately after.
- **No external transmission.** Passwords are never sent to a
  third-party API or service; all checks are local.
- **Secure randomness.** All password generation uses `secrets`, never
  `random`.
- **Input validation & limits.** Password length is capped
  server-side (256 characters for the analyze endpoint; 8–128 for
  generation) to avoid pathological input.
- **Safe error handling.** A generic Flask 500 handler ensures no
  stack trace or internal detail is ever shown to the user.
- **HTTP security headers**, set on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - A restrictive `Content-Security-Policy` that only allows
    same-origin scripts/styles (this app doesn't load any third-party
    JS/CSS).
- **No hardcoded secrets** and no unnecessary dependencies (only
  Flask and pytest).

## 14. Installation (Windows)

1. Open the project folder in **VS Code** (or any terminal).
2. Create a virtual environment:

   ```powershell
   python -m venv venv
   ```

3. Activate it (PowerShell):

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

   > If PowerShell blocks the script, you may need to run:
   > `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`

4. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

*(macOS/Linux users: activate with `source venv/bin/activate` instead
of step 3.)*

## 15. How to Run

```powershell
python app.py
```

Then open your browser to:

```
http://127.0.0.1:5000
```

Type a password into the "Enter Password" field to see live feedback,
or use the "Secure Password Generator" panel to generate one.

## 16. Testing

Tests live in `tests/test_analyzer.py` and `tests/test_generator.py`,
covering (among others): an empty password, a very short password,
`123456`, `password`, `password123`, `Password123`, `Password123!`, a
long random password, a long predictable passphrase, repeated
characters, sequential characters, and a password containing all
character types.

Run all tests with:

```powershell
pip install -r requirements.txt
pytest tests/
```

or, without pytest:

```powershell
python -m unittest discover tests
```

## 17. Example Screens

**Analyzer**

```
Enter Password
[ *********************** ] [Show]

Strength: Weak
Score: 37 / 100
Estimated entropy: ~55.4 bits (estimate)

Security Checks:
✓ Minimum length     ✗ Recommended length
✓ Uppercase letter   ✓ Lowercase letter
✓ Number             ✓ Special character
✓ Good character variety

Warnings:
⚠ Matches a common/leaked password or an obvious variation of one.

Recommendations:
• Consider 16+ characters for stronger protection.
• Avoid common words, patterns, and predictable substitutions.
```

**Generator**

```
Length: 16
☑ Uppercase  ☑ Lowercase  ☑ Numbers  ☑ Special Characters
[ Generate Password ]
Generated: 7$kQmZ2!vRt9#LpA
[ Copy ]
```

## 18. Limitations

- The common-password list is a small local sample, not a real
  leaked-password database (by design — no downloads, no external
  services).
- Pattern and leetspeak detection is intentionally simple and will not
  catch every possible variation an attacker's tooling might try.
- Entropy is a mathematical estimate based on character-class
  diversity, not a real measurement of how guessable a password is —
  see Section 9.
- This tool does not check whether a password has appeared in an
  actual data breach (that would require an external service, which
  this project deliberately avoids for privacy reasons).
- This is an educational project, not a certified security product.

## 19. Future Enhancements

- Support for a larger, downloadable common-password list (kept local)
- Passphrase-specific scoring mode (e.g. for Diceware-style passwords)
- Configurable password policy exposed in the UI
- Optional integration with a *local, offline* breach-list format
  (e.g. a k-anonymity style local lookup) without any network calls
- Internationalization of the UI

## 20. Ethical / Privacy Considerations

This project is built strictly for **defensive** password-security
education. It:

- Never stores, logs, or transmits a user's real password.
- Never sends any password to a third-party or external API.
- Uses cryptographically secure randomness for anything
  security-related.
- Is not intended to help anyone crack, guess, or gain unauthorized
  access to accounts — it exists to help people choose *their own*
  passwords more safely and to teach the reasoning behind password
  security.
