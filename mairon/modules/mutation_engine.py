import hashlib
import requests

LEET_MAP = {
    "a": "@",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "$",
    "t": "7",
    "l": "1",
    "b": "8",
    "g": "9",
}

COMMON_SUFFIXES = ["1", "12", "123", "1234", "!", "!!", "@", "#", "2023", "2024", "01", "007", "69", "99"]

HIBP_API     = "https://api.pwnedpasswords.com/range/"
HIBP_HEADERS = {
    "User-Agent":  "Mairon-Password-Auditor/0.1",
    "Add-Padding": "true",
}

def apply_leet(word: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in word)


def generate_mutations(password: str) -> list:
    mutations = set()
    lower = password.lower()

    leet = apply_leet(lower)
    if leet != lower:
        mutations.add(leet)

    leet_orig = apply_leet(password)
    if leet_orig != password:
        mutations.add(leet_orig)

    mutations.add(password.capitalize())

    mutations.add(password.upper())

    mutations.add(password[::-1])

    mutations.add(apply_leet(password[::-1]))

    for suffix in COMMON_SUFFIXES:
        mutations.add(password + suffix)
        mutations.add(lower + suffix)
        mutations.add(password.capitalize() + suffix)

    for suffix in COMMON_SUFFIXES[:5]:
        mutations.add(leet + suffix)
        mutations.add(leet_orig + suffix)

    mutations.discard(password)

    return sorted(mutations) 


def _check_hibp(password: str) -> dict:

    sha1  = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(
            HIBP_API + prefix,
            headers=HIBP_HEADERS,
            timeout=5 
        )
        response.raise_for_status()
    except Exception:
        return {"found": False, "count": 0, "checked": False}

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return {"found": True, "count": int(parts[1]), "checked": True}

    return {"found": False, "count": 0, "checked": True}

def analyze_mutations(password: str, offline: bool = False) -> dict:

    mutations     = generate_mutations(password)
    results       = []
    breached_count = 0

    for mutation in mutations:
        entry = {
            "mutation":     mutation,
            "breached":     False,
            "breach_count": 0,
            "checked":      False,
        }

        if not offline:
            check = _check_hibp(mutation)
            entry["breached"]     = check["found"]
            entry["breach_count"] = check["count"]
            entry["checked"]      = check["checked"]

            if check["found"]:
                breached_count += 1

        results.append(entry)

    total = len(results)

    if offline:
        rating = "Unknown (offline mode — breach check skipped)"
    elif breached_count == 0:
        rating = "Low Risk"
    elif breached_count <= 3:
        rating = "Medium Risk"
    else:
        rating = "High Risk"

    return {
        "mutations":          results,
        "total_mutations":    total,
        "breached_mutations": breached_count,
        "rating":             rating,
    }
