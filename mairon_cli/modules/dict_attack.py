import os
import hashlib
import subprocess

from mairon_cli.utils import get_wordlist_path

DICT_ATTACK_BIN = os.path.expanduser("~/.local/bin/mairon_dict_attack")
ATTACK_TIMEOUT = 180

def run_dict_attack(password: str, wordlist_path: str = None) -> dict:
    if not os.path.exists(DICT_ATTACK_BIN):
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error": (
                "dict_attack binary not found. "
                "Run 'make install' from the mairon directory to compile it."
            ),
        }
    if wordlist_path is None:
        wordlist_path = get_wordlist_path()

    if wordlist_path is None or not os.path.exists(wordlist_path):
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error": (
                "Wordlist not found. "
                "Run 'mairon --update-wordlist' to download rockyou.txt, "
                "or supply your own with --wordlist /path/to/wordlist.txt"
            ),
        }
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest()
    try:
        result = subprocess.run(
            [DICT_ATTACK_BIN, sha1_hash, wordlist_path],
            capture_output=True,
            text=True,
            timeout=ATTACK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  float(ATTACK_TIMEOUT),
            "error":         f"Attack timed out after {ATTACK_TIMEOUT} seconds. Password not found within limit.",
        }
    except FileNotFoundError:
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error":         "Binary execution failed. Re-run 'make build-cpp'.",
        }
    except Exception as e:
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error":         str(e),
        }
        
    lines = result.stdout.strip().split("\n")

    if len(lines) < 3:
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error":         f"Unexpected binary output: {result.stdout!r}",
        }

    try:
        status        = lines[0].strip()
        words_checked = int(lines[1].strip())
        time_elapsed  = round(float(lines[2].strip()), 4)
    except (ValueError, IndexError) as e:
        return {
            "found":         False,
            "words_checked": 0,
            "time_elapsed":  0.0,
            "error":         f"Failed to parse binary output: {e}",
        }

    return {
        "found":         status == "FOUND",
        "words_checked": words_checked,
        "time_elapsed":  time_elapsed,
        "error":         None,
    }
