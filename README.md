# Vaultline — Password Strength Analyzer

Built for Andropedia Technical Recruitment 2026 · Round 1

Vaultline checks a password against a set of simple, explainable rules and
tells you how strong it is, why, and how to improve it — plus an entropy
estimate, a rough crack-time estimate, and a strong-password generator.

---

## Technologies used

- **Backend:** Python 3 + Flask (a small REST API, two endpoints)
- **Frontend:** plain HTML, CSS, and vanilla JavaScript (no build step,
  no framework — just fetch() calls to the backend)
- **Libraries:** `flask-cors` (lets the standalone HTML file call the
  API), Python's built-in `re`, `math`, `random`, `string` modules

No database is needed — the analyzer is stateless; every request is
scored independently.

---

## How to run the application

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Start the backend:
   ```
   python app.py
   ```
   This runs the API at `http://localhost:5000`.
3. Open `frontend.html` directly in a browser (double-click it, or use
   a simple static server). It talks to the backend automatically.
   If your backend runs somewhere other than `localhost:5000`, change
   the `API_BASE` constant at the top of the `<script>` block in
   `frontend.html`.

No password is ever stored — each keystroke is analyzed live and
discarded; nothing is written to disk or a database.

---

## How the strength score is calculated

Every password starts at 0 points. Points are added for good
properties, up to a maximum of **100**:

| Check | Points | Notes |
|---|---|---|
| Length ≥ 12 chars | 25 | Full length credit |
| Length 8–11 chars | 15 | Partial credit |
| Length 6–7 chars | 5 | Minimal credit |
| Length < 6 chars | 0 | |
| Has uppercase letter | 10 | |
| Has lowercase letter | 10 | |
| Has a number | 10 | |
| Has a special character | 15 | Weighted highest — biggest boost to the character set attackers must search |
| No 3+ repeated character in a row (e.g. `aaa`) | 10 | |
| No predictable sequence (e.g. `123`, `abc`, `qwe`) | 10 | |
| Not on the common-password list | 10 | If the password **is** a known common password, the score is force-capped at 10 regardless of other points, since a common password is crackable in seconds no matter what else is true about it |

**Final rating:**
- 0–40 → **Weak**
- 41–70 → **Medium**
- 71–100 → **Strong**

This is a simple additive rubric rather than a machine-learning model
on purpose — it's transparent, every point can be traced back to one
clear rule, and it's easy to explain and defend in review.

### Entropy estimate (bonus)

```
entropy_bits = password_length × log2(character_set_size)
```

`character_set_size` is the sum of the character pools actually used
(26 for lowercase, 26 for uppercase, 10 for digits, ~32 for common
special characters). This is the standard "brute-force" entropy
formula — it assumes an attacker doesn't know anything about the
password's structure beyond which character types it draws from.

### Crack-time estimate (bonus)

```
seconds_to_crack = 2^entropy_bits ÷ guesses_per_second
```

**Assumption stated explicitly:** we assume an attacker can attempt
**1,000,000,000 (1 billion) guesses per second**, which is roughly
what's achievable with modern GPU-based offline brute-force attacks
against a fast, unsalted hash. This is a worst-case assumption — real
systems that use slow hashing (bcrypt/argon2) and rate-limiting would
take far longer to attack. It's meant as a relative comparison
between passwords, not a precise real-world guarantee.

---

## Edge cases handled

- Empty password → instantly rated Weak with a clear message, no crash
- Very short passwords (1–5 characters)
- Passwords that are only letters, or only numbers
- Repeated characters (`aaaaaa`, `111111`)
- Sequential/predictable patterns (`123456`, `abcdef`, `qwerty`)
- Common passwords (`password`, `123456`, `letmein`, etc. — score is
  force-capped even if the password is long)
- Passwords with unicode/special symbols
- Backend never crashes on malformed JSON — falls back to an empty
  password instead of throwing an error

---

## Bonus features implemented

- ✅ **Password generator** — customizable length (6–32) and character
  types (uppercase / lowercase / digits / special), returned along
  with its own strength analysis
- ✅ **Entropy estimate** — shown in bits on the dial
- ✅ **Crack-time estimate** — human-readable (seconds → centuries),
  assumptions stated above
- ✅ **Web application** — full frontend included (`frontend.html`),
  not just a CLI
- ✅ **Additional feature — live analysis:** the frontend analyzes the
  password as you type (debounced), not just on submit
- ✅ **Additional feature — show/hide password toggle** on the input
- ✅ **Additional feature — copy-to-clipboard** for generated passwords

---

## Project structure

```
app.py           → Flask backend (scoring logic + API routes)
frontend.html    → Self-contained web frontend (HTML/CSS/JS)
requirements.txt → Python dependencies
README.md        → This file
```

---

## Screenshots / demo

_Add 2–3 screenshots here before submitting:_
1. A weak password being analyzed (e.g. `password1`)
2. A strong password being analyzed
3. The password generator producing a new password

To capture these: run the app as described above, try a few passwords
in the browser, and take screenshots of the analyzer panel showing
the dial, checklist, and suggestions.
