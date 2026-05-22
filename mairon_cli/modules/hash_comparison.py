import hashlib

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

ALGO_INFO = {
    "MD5": {
        "gpu_speed":   "~60 billion hashes/sec",
        "crackable":   True,
        "status":      "Broken",
        "rating":      "Never use for passwords — broken and catastrophically fast",
        "use_case":    "File integrity checks only (and poorly even there)",
    },
    "SHA-1": {
        "gpu_speed":   "~20 billion hashes/sec",
        "crackable":   True,
        "status":      "Deprecated",
        "rating":      "Deprecated — collision vulnerabilities known since 2017",
        "use_case":    "Legacy systems only. Avoid for any new implementation",
    },
    "SHA-256": {
        "gpu_speed":   "~10 billion hashes/sec",
        "crackable":   True,
        "status":      "Secure (but wrong tool for passwords)",
        "rating":      "Secure hash function — but too fast for password storage",
        "use_case":    "Digital signatures, TLS, file integrity. Don't use for raw password storage",
    },
    "bcrypt": {
        "gpu_speed":   "~20,000 hashes/sec (cost=12)",
        "crackable":   False,
        "status":      "Recommended",
        "rating":      "Intentionally slow and specifically designed for passwords",
        "use_case":    "Password storage. The deliberate slowness defeats brute-force",
    },
}

def compare_hashes(password: str) -> dict:

    encoded = password.encode("utf-8")
    results = {}

    results["MD5"] = {
        "hash": hashlib.md5(encoded).hexdigest(),
        **ALGO_INFO["MD5"],
    }

    results["SHA-1"] = {
        "hash": hashlib.sha1(encoded).hexdigest(),
        **ALGO_INFO["SHA-1"],
    }

    results["SHA-256"] = {
        "hash": hashlib.sha256(encoded).hexdigest(),
        **ALGO_INFO["SHA-256"],
    }

    if BCRYPT_AVAILABLE:
        salt   = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(encoded, salt)
        results["bcrypt"] = {
            "hash": hashed.decode("utf-8"),
            **ALGO_INFO["bcrypt"],
        }
    else:
        results["bcrypt"] = {
            "hash":      "[bcrypt not installed — run: pip install bcrypt]",
            **ALGO_INFO["bcrypt"],
        }

    return results
