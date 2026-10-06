# Vaultline — Password Strength Analyzer & Generator

Built for **Andropedia Technical Recruitment 2026 · Round 1**

Vaultline checks a password against a set of simple, explainable rules and tells you how strong it is, why, and how to improve it — plus an entropy estimate, a rough crack-time estimate, and a strong-password generator.

---

## 🛠️ Technologies Used

- **Backend:** Python 3 + Flask (a small REST API with two endpoints)
- **Frontend:** Plain HTML, CSS, and vanilla JavaScript (no build step, no framework — uses native `fetch()` calls to the backend)
- **Libraries:** `flask-cors` (enables cross-origin requests from the static HTML file), Python's built-in `re`, `math`, `random`, and `string` modules

> **Note:** No database is needed — the analyzer is stateless; every request is scored independently in memory.

---

## 🚀 How to Run the Application

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the backend:**
   ```bash
   python app.py
   ```
   *This runs the API at `http://localhost:5000`.*

3. **Open the frontend:**
   Open `frontend.html` directly in a web browser (double-click it, or use a simple static server). It talks to the backend automatically. 
   *(If your backend runs somewhere other than `localhost:5000`, change the `API_BASE` constant at the top of the `<script>` block in `frontend.html`.)*

> **Privacy Notice:** No password is ever stored — each keystroke is analyzed live and discarded; nothing is written to disk or a database.

---

## 📊 How the Strength Score is Calculated

Every password starts at **0 points**. Points are added for good properties, up to a maximum of **100**:

| Check | Points | Notes |
| :--- | :---: | :--- |
| **Length $\ge$ 12 chars** | `25` | Full length credit |
| **Length 8–11 chars** | `15` | Partial credit |
| **Length 6–7 chars** | `5` | Minimal credit |
| **Length < 6 chars** | `0` | No credit |
| **Has uppercase letter** | `10` | Includes `A-Z` |
| **Has lowercase letter** | `10` | Includes `a-z` |
| **Has a number** | `10` | Includes `0-9` |
| **Has a special character** | `15` | Weighted highest — biggest boost to character set attackers must search |
| **No 3+ repeated characters in a row** | `10` | Prevents patterns like `aaa` or `111` |
| **No predictable sequence** | `10` | Prevents patterns like `123`, `abc`, `qwe` |
| **Not on common-password list** | `10` | Checks against known common password dictionary |

### 🛑 Override Rule for Common Passwords
If the password is a known common password, the score is **force-capped at 10** regardless of other points, since a common password is crackable in seconds no matter what else is true about it.

### Final Rating Tiers
- **0–40** $\rightarrow$ **Weak**
- **41–70** $\rightarrow$ **Medium**
- **71–100** $\rightarrow$ **Strong**

*This is a simple additive rubric rather than a machine-learning model on purpose — it's transparent, every point can be traced back to one clear rule, and it's easy to explain and defend in review.*

---

## 🧮 Mathematical Formulas

### Entropy Estimate (Bonus)

$$\text{entropy\_bits} = \text{password\_length} \times \log_2(\text{character\_set\_size})$$

`character_set_size` is the sum of the character pools actually used:
- `26` for lowercase
- `26` for uppercase
- `10` for digits
- `~32` for common special characters

*This is the standard "brute-force" entropy formula — it assumes an attacker doesn't know anything about the password's structure beyond which character types it draws from.*

### Crack-Time Estimate (Bonus)

$$\text{seconds\_to\_crack} = \frac{2^{\text{entropy\_bits}}}{\text{guesses\_per\_second}}$$

- **Assumption stated explicitly:** We assume an attacker can attempt $1,000,000,000$ ($10^9$ / 1 billion) guesses per second, which is roughly what's achievable with modern GPU-based offline brute-force attacks against a fast, unsalted hash. 
- *This is a worst-case assumption — real systems that use slow hashing (`bcrypt`/`argon2`) and rate-limiting would take far longer to attack. It's meant as a relative comparison between passwords, not a precise real-world guarantee.*

---

## 🔍 Edge Cases Handled

- **Empty password:** Instantly rated *Weak* with a clear message, no crash.
- **Very short passwords:** (1–5 characters) handled gracefully.
- **Single character sets:** Passwords that are only letters or only numbers.
- **Repeated characters:** Detects sequential duplicates (`aaaaaa`, `111111`).
- **Sequential/predictable patterns:** Detects common keyboard/alphabet sequences (`123456`, `abcdef`, `qwerty`).
- **Common passwords:** (`password`, `123456`, `letmein`, etc. — score is force-capped even if the password is long).
- **Special symbols:** Support for passwords with Unicode/special characters.
- **Malformed input:** Backend never crashes on malformed JSON — falls back to an empty password instead of throwing an error.

---

## 🔥 Bonus Features Implemented

- 🎲 **Password generator:** Customizable length (6–32) and character types (uppercase / lowercase / digits / special), returned along with its own strength analysis.
- ⚡ **Entropy estimate:** Shown in bits on the dial.
- ⏱️ **Crack-time estimate:** Human-readable (seconds $\rightarrow$ centuries), assumptions explicitly stated.
- 🌐 **Web application:** Full frontend included (`frontend.html`), not just a CLI.
- ⌨️ **Live analysis:** The frontend analyzes the password as you type (debounced), not just on submit.
- 👁️ **Show/hide password toggle:** Quick visibility toggle on the input field.
- 📋 **Copy-to-clipboard:** One-click copy button for generated passwords.

---

## 📁 Project Structure

```text
vaultline/
├── app.py           # Flask backend (scoring logic + API routes)
├── frontend.html    # Self-contained web frontend (HTML/CSS/JS)
├── requirements.txt # Python dependencies
└── README.md        # Project documentation
```
