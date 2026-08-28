"""
Password Strength Analyzer - Backend
--------------------------------------
This is a simple Flask backend. It exposes an API that takes a
password as input and returns:
  - a strength rating (Weak / Medium / Strong)
  - a score out of 100
  - checklist feedback (what's good, what's missing)
  - suggestions for improvement
  - bonus: entropy estimate + rough crack-time estimate
  - bonus: a random strong password generator

Everything is written using plain if/else logic and simple loops so
it's easy to read and explain in an interview.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import math
import random
import string
import os

# Set template_folder='.' so Flask can find frontend.html in the root directory
app = Flask(__name__, template_folder='.')
CORS(app)  # allows the frontend file to call this API

# ---------------------------------------------------------
# STEP 1: A small list of common/weak passwords to reject.
# ---------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "qwerty",
    "abc123", "password1", "111111", "letmein", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football"
}

# Sequences we consider "predictable" if they appear inside the password
SEQUENTIAL_PATTERNS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"
]


def has_repeated_chars(password):
    """Returns True if the same character repeats 3+ times in a row."""
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True
    return False


def has_sequential_pattern(password):
    """Returns True if the password contains a 3+ character chunk of a known sequence."""
    lower_pw = password.lower()
    for seq in SEQUENTIAL_PATTERNS:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in lower_pw or chunk[::-1] in lower_pw:
                return True
    return False


def analyze_password(password):
    """Main scoring function."""
    checklist = []
    suggestions = []
    score = 0

    if password is None or password == "":
        return {
            "strength": "WEAK",
            "score": 0,
            "checklist": [{"pass": False, "message": "Password is empty"}],
            "suggestions": ["Please enter a password"],
            "entropy_bits": 0,
            "estimated_crack_time": "instantly"
        }

    length = len(password)

    # --- Length check ---
    if length >= 12:
        score += 25
        checklist.append({"pass": True, "message": "Good length (12+ characters)"})
    elif length >= 8:
        score += 15
        checklist.append({"pass": True, "message": "Acceptable length (8-11 characters)"})
        suggestions.append("Use at least 12 characters for better security")
    elif length >= 6:
        score += 5
        checklist.append({"pass": False, "message": "Too short (only 6-7 characters)"})
        suggestions.append("Use at least 12 characters")
    else:
        checklist.append({"pass": False, "message": "Way too short (under 6 characters)"})
        suggestions.append("Use at least 12 characters")

    # --- Character type checks ---
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    if has_upper:
        score += 10
        checklist.append({"pass": True, "message": "Contains uppercase letters"})
    else:
        checklist.append({"pass": False, "message": "No uppercase letters"})
        suggestions.append("Add at least one uppercase letter")

    if has_lower:
        score += 10
        checklist.append({"pass": True, "message": "Contains lowercase letters"})
    else:
        checklist.append({"pass": False, "message": "No lowercase letters"})
        suggestions.append("Add at least one lowercase letter")

    if has_digit:
        score += 10
        checklist.append({"pass": True, "message": "Contains numbers"})
    else:
        checklist.append({"pass": False, "message": "No numbers"})
        suggestions.append("Add at least one number")

    if has_special:
        score += 15
        checklist.append({"pass": True, "message": "Contains special characters"})
    else:
        checklist.append({"pass": False, "message": "No special characters"})
        suggestions.append("Add a special character (e.g. ! @ # $ %)")

    # --- Repeated characters check ---
    if not has_repeated_chars(password):
        score += 10
        checklist.append({"pass": True, "message": "No repeated character sequences"})
    else:
        checklist.append({"pass": False, "message": "Contains repeated characters (e.g. 'aaa')"})
        suggestions.append("Avoid repeating the same character multiple times in a row")

    # --- Sequential pattern check ---
    if not has_sequential_pattern(password):
        score += 10
        checklist.append({"pass": True, "message": "No predictable sequences"})
    else:
        checklist.append({"pass": False, "message": "Contains a predictable sequence (e.g. '123', 'abc')"})
        suggestions.append("Avoid predictable patterns or sequences")

    # --- Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 10)
        checklist.append({"pass": False, "message": "This is a very common password"})
        suggestions.append("Avoid using common/well-known passwords")
    else:
        score += 10
        checklist.append({"pass": True, "message": "Not a common password"})

    score = min(score, 100)

    # --- Final classification ---
    if score <= 40:
        strength = "WEAK"
    elif score <= 70:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    # --- Bonus: Entropy estimate ---
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    entropy_bits = round(length * math.log2(charset_size), 2) if charset_size > 0 else 0

    # --- Bonus: Crack time estimate ---
    guesses_per_second = 1_000_000_000
    total_combinations = 2 ** entropy_bits if entropy_bits > 0 else 1
    seconds_to_crack = total_combinations / guesses_per_second
    estimated_crack_time = format_time(seconds_to_crack)

    return {
        "strength": strength,
        "score": score,
        "checklist": checklist,
        "suggestions": suggestions,
        "entropy_bits": entropy_bits,
        "estimated_crack_time": estimated_crack_time
    }


def format_time(seconds):
    """Turns a number of seconds into a human-readable string."""
    if seconds < 1:
        return "instantly"
    minute = 60
    hour = minute * 60
    day = hour * 24
    year = day * 365

    if seconds < minute:
        return f"{int(seconds)} seconds"
    elif seconds < hour:
        return f"{int(seconds / minute)} minutes"
    elif seconds < day:
        return f"{int(seconds / hour)} hours"
    elif seconds < year:
        return f"{int(seconds / day)} days"
    elif seconds < year * 100:
        return f"{int(seconds / year)} years"
    else:
        return "centuries"


def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    """Generates a random strong password."""
    pool = ""
    if use_upper:
        pool += string.ascii_uppercase
    if use_lower:
        pool += string.ascii_lowercase
    if use_digits:
        pool += string.digits
    if use_special:
        pool += "!@#$%^&*()-_=+"

    if pool == "":
        pool = string.ascii_letters + string.digits

    return "".join(random.choice(pool) for _ in range(length))


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------

@app.route("/")
def home():
    """Serves the frontend website"""
    return render_template("frontend.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_route():
    """Expects JSON: { "password": "..." }"""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    result = analyze_password(password)
    return jsonify(result)


@app.route("/api/generate", methods=["POST"])
def generate_route():
    """Expects JSON: { "length": 12, "uppercase": true, ... }"""
    data = request.get_json(silent=True) or {}
    length = int(data.get("length", 12))
    length = max(4, min(length, 64))

    generated = generate_password(
        length=length,
        use_upper=data.get("uppercase", True),
        use_lower=data.get("lowercase", True),
        use_digits=data.get("digits", True),
        use_special=data.get("special", True),
    )
    analysis = analyze_password(generated)
    return jsonify({"password": generated, "analysis": analysis})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
