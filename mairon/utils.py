import os
import sys
import gzip
import shutil

#path here

MAIRON_DIR    = os.path.expanduser("~/.mairon")
WORDLIST_DIR  = os.path.join(MAIRON_DIR, "wordlists")
WORDLIST_PATH = os.path.join(WORDLIST_DIR, "rockyou.txt")

# rockyou.tst file
KALI_WORDLIST    = "/usr/share/wordlists/rockyou.txt"
KALI_WORDLIST_GZ = "/usr/share/wordlists/rockyou.txt.gz"
ROCKYOU_URL = (
    "https://github.com/brannondorsey/naive-hashcat/"
    "releases/download/data/rockyou.txt"
)


def get_wordlist_path() -> str:
    if os.path.exists(WORDLIST_PATH):return WORDLIST_PATH
    if os.path.exists(KALI_WORDLIST): return KALI_WORDLIST
    return None


def download_rockyou(force: bool = False) -> None:
    """
    Download rockyou.txt
    """
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    #already downloaded
    if os.path.exists(WORDLIST_PATH) and not force:
        size_mb = os.path.getsize(WORDLIST_PATH) / (1024 * 1024)
        print(f"  rockyou.txt already exists ({size_mb:.0f} MB) at {WORDLIST_PATH}")
        print("  Run 'mairon --update-wordlist' to force re-download.")
        return

    #kali pre-installed
    if os.path.exists(KALI_WORDLIST):
        print(f"  Found system rockyou.txt at {KALI_WORDLIST}")
        print(f"  Creating symlink → {WORDLIST_PATH} ...")
        if os.path.islink(WORDLIST_PATH):
            os.remove(WORDLIST_PATH)
        os.symlink(KALI_WORDLIST, WORDLIST_PATH)
        print("  ✓ Done. No download needed.")
        return

    # if kali zipped
    if os.path.exists(KALI_WORDLIST_GZ):
        print(f"  Found {KALI_WORDLIST_GZ} — extracting (this may take a minute)...")
        with gzip.open(KALI_WORDLIST_GZ, "rb") as f_in:
            with open(WORDLIST_PATH, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"  ✓ Extracted to {WORDLIST_PATH}")
        return

    # else dowload
    try:
        import requests
    except ImportError:
        print("  ERROR: 'requests' library not installed. Run: pip install requests")
        sys.exit(1)

    print(f"  Downloading rockyou.txt (~133 MB) from GitHub...")
    print(f"  Saving to {WORDLIST_PATH}")
    print("  Please wait...\n")

    try:
        response = requests.get(ROCKYOU_URL, stream=True, timeout=30)
        response.raise_for_status()

        total  = int(response.headers.get("content-length", 0))
        done   = 0
        chunk  = 8192

        with open(WORDLIST_PATH, "wb") as f:
            for data in response.iter_content(chunk_size=chunk):
                f.write(data)
                done += len(data)
                if total:
                    pct = done / total * 100
                    mb_done  = done  / 1024 / 1024
                    mb_total = total / 1024 / 1024
                    sys.stdout.write(
                        f"\r  [{pct:5.1f}%]  {mb_done:.1f} MB / {mb_total:.1f} MB"
                    )
                    sys.stdout.flush()

        print(f"\n\n  ✓ rockyou.txt downloaded successfully.")

    except requests.exceptions.ConnectionError:
        print("\n  ERROR: No internet connection. Supply your own wordlist with --wordlist.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"\n  ERROR: Download failed — {e}")
        print("  Supply your own wordlist with --wordlist /path/to/wordlist.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        if os.path.exists(WORDLIST_PATH):
            os.remove(WORDLIST_PATH)
        print("\n  Download cancelled.")
        sys.exit(0)
