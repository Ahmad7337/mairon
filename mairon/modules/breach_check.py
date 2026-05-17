import hashlib
import requests

HIBP_API     = "https://api.pwnedpasswords.com/range/"
HIBP_HEADERS = {
    "User-Agent":   "Mairon-Password-Auditor/0.1",
    "Add-Padding":  "true", 
}
TIMEOUT = 10

def check_breach(password: str) -> dict:

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix    = sha1_hash[:5]   
    suffix    = sha1_hash[5:]   

    try:
        response = requests.get(
            HIBP_API + prefix,
            headers=HIBP_HEADERS,
            timeout=TIMEOUT
        )
        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        return {
            "found": False,
            "count": 0,
            "error": "No internet connection. Use --offline to skip this module."
        }
    except requests.exceptions.Timeout:
        return {
            "found": False,
            "count": 0,
            "error": "HIBP API timed out. Try again or use --offline."
        }
    except requests.exceptions.HTTPError as e:
        return {
            "found": False,
            "count": 0,
            "error": f"HIBP API error: {e}"
        }
    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return {
                "found": True,
                "count": int(parts[1]),
                "error": None
            }
    return {"found": False, "count": 0, "error": None}
