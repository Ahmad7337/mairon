import re

KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty", "ytrewq",
    "asdf",   "asdfg", "sdfgh", "gfdsa",
    "zxcvb",  "zxcvbn", "nbvcxz",
    "1234",   "12345",  "123456", "1234567", "12345678", "123456789",
    "0987",   "09876",  "098765", "0987654",
    "abcd",   "abcde",  "abcdef",
]

COMMON_WORDS = [
    "password", "passwd", "pass", "admin", "login",
    "welcome", "monkey", "dragon", "master", "sunshine",
    "iloveyou", "princess", "letmein", "football", "shadow",
    "superman", "batman", "trustno1", "hello", "qwerty",
    "abc123", "password1", "123abc",
]

COMMON_SUFFIXES = ["123", "1234", "12345", "1", "2", "!", "!!", "!!!", "@", "#", "01", "007"]


def detect_patterns(password: str) -> dict:

    issues = []
    lower  = password.lower()

    for walk in KEYBOARD_WALKS:
        if walk in lower:
            issues.append(f"Keyboard walk detected: '{walk}'")

    for word in COMMON_WORDS:
        if word in lower:
            issues.append(f"Common word detected: '{word}'")

    if re.search(r"(19|20)\d{2}", password):
        issues.append("Year pattern detected (e.g. 2023, 1999) — very predictable")

    if re.search(r"(.)\1{2,}", password):
        match = re.search(r"(.)\1{2,}", password)
        issues.append(f"Repeated characters detected: '{match.group()}'")

    if password.isdigit():
        issues.append("Password is entirely digits — no letters or symbols")

    if password.isalpha():
        issues.append("Password is entirely letters — no digits or symbols")

    for suffix in COMMON_SUFFIXES:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            base = lower[: -len(suffix)]
            if base.isalpha():  
                issues.append(
                    f"Common suffix padding detected: base word + '{suffix}'"
                )
                break 

    if re.match(r"^[A-Z][a-z]{2,}(\d+)[!@#$%]?$", password):
        issues.append(
            "Predictable structure: Capital letter + word + numbers — extremely common pattern"
        )

    for word in COMMON_WORDS[:10]:
        if word[::-1] in lower:
            issues.append(f"Reversed common word detected: '{word[::-1]}' ('{word}' backwards)")

    if len(issues) == 0:
        rating = "Clean"
    elif len(issues) <= 2:
        rating = "Medium Risk"
    else:
        rating = "High Risk"

    return {
        "issues":      issues,
        "issue_count": len(issues),
        "rating":      rating,
    }
