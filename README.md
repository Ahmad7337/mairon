# mairon
> **Current release : v0.1 (Alpha)** It is under active development and may contain bugs or incomplete features.


Mairon is CLI-based password audit and analysis tool for Linux, developed as a CEH course project at the NETSOL Institute of Artificial Intelligence (NIAI) under NAVTTC.

> *"For nothing is evil in the beginning, even Sauron was not so"*
> — Tolkien's legendarium

Mairon takes a password, runs it through a series of analysis modules, and will tell you how weak, leaked, or predictable it is before an attacker finds out for you.

The name comes from Tolkien's *Lord of the Rings*, the name of the titular antagonist; Sauron. Before his corruption, Sauron was called **Mairon** — meaning *the Admirable*. This tool has that same duality: the same techniques that an attacker uses to crack passwords are here turned toward defense and awareness. Like CEH itself — ethical, but fully aware and capable of the dark side.

---

## What It Does

You run `mairon`, enter a password, and it tells you:

- If password has already been leaked in a public breach
- How strong it actually is (password entropy).
- If it follows predictable patterns that people use and attackers exploit
- How quickly it can be cracked by an dictionary attack
- What happens when common mutations are applied to it
- How its hash holds up across different algorithms
- A final score out of 100 aggregating all of the above

Everything outputs to the terminal. Add `-r` and it writes a report file instead.

---

## Installation

> **Requirements:** Python 3.8+, GCC (for C++ module), Linux

```bash
git clone https://github.com/Ahmad7337/mairon
cd mairon
make install
```

On first install, Mairon will automatically download `rockyou.txt` (the standard 14M-entry password wordlist) to its local data directory. You can update it anytime with:

```bash
mairon --update-wordlist
```

Or point it to your own wordlist:

```bash
mairon -p mypassword -m 4 --wordlist /path/to/custom.txt
```

---

## Usage

```bash
# Run all modules
mairon -p <password> -a

# Run specific modules (1 through 8)
mairon -p <password> -m 1,3,5

# Run all modules and generate a report file
mairon -p <password> -a -r

# Skip breach check (offline / air-gapped use)
mairon -p <password> -a --offline

# Update wordlist
mairon --update-wordlist

# Help
mairon --help
```

> **Note:** Password input is hidden from terminal output using Python's `getpass`. Your password is never stored or logged anywhere.

---

## Modules

| # | Module | Status | Language | Description |
|---|--------|--------|----------|-------------|
| 1 | Breach database check | v0.1 Alpha | Python | Checks HIBP Pwned Passwords API using k-anonymity — only the first 5 chars of your password's SHA-1 hash ever leave your machine |
| 2 | Entropy calculator | v0.1 Alpha | Python | Calculates password entropy in bits using charset size and length. Gives a concrete numeric weakness rating |
| 3 | Pattern detector | v0.1 Alpha | Python | Detects keyboard walks, year suffixes, repeated characters, padding, and other patterns attackers specifically target |
| 4 | Dictionary attack simulation | v0.1 Alpha | C++ | Runs password hash against rockyou.txt and reports if and how fast it would be cracked. Written in C++ for realistic speed simulation |
| 5 | Mutation engine | v0.1 Alpha | Python | Applies common human mutations (leet speak, capitalization, appended symbols) and tests each variant against breach data and wordlists |
| 6 | Hash format comparison | v0.1 Alpha | Python | Generates your password's hash in MD5, SHA-1, SHA-256, and bcrypt, then explains the crackability difference between each |
| 7 | Report generator | v0.1 Alpha | Python | Dumps full audit results to a formatted `.txt` or `.html` file in `/reports`. Password is redacted in all output |
| 8 | Scoring engine | v0.1 Alpha | Python | Aggregates results from all modules into a 0–100 risk score with weighted contributions per module |

### Scoring Weights

| Module | Weight |
|--------|--------|
| Breach database check | 25 pts |
| Entropy calculator | 20 pts |
| Pattern detector | 20 pts |
| Dictionary attack simulation | 15 pts |
| Mutation engine | 10 pts |
| Hash format comparison | 10 pts |

---

## Project Scope

Mairon is strictly a **defensive awareness tool**. It does not:

- Store passwords
- Send full passwords or hashes to any server
- Crack other people's passwords
- Interact with any system other than HIBP's public, privacy-safe API

It is designed for:

- Security students learning password attack concepts
- Developers auditing their own credential policies
- IT teams running internal password hygiene checks
- Anyone curious about how crackable their passwords actually are

---

## Tech Stack

```
Language        Use
─────────────────────────────────────────
Python 3.8+     All modules except dict attack
C++             Dictionary attack simulation (speed-critical)
Bash / Make     Build pipeline, install helpers

Dependencies
─────────────────────────────────────────
requests        HIBP API calls
colorama        Color-coded terminal output
hashlib         SHA-1 / SHA-256 (stdlib)
argparse        CLI flag handling (stdlib)
getpass         Hidden password input (stdlib)
subprocess      Python → C++ binary bridge
```

---

## Project Structure (expected at full release)

```
mairon/
├── main.py                  ← CLI entry point
├── pyproject.toml           ← Package config and dependencies
├── Makefile                 ← Builds C++ binary on install
├── modules/
│   ├── breach_check.py
│   ├── entropy.py
│   ├── pattern_detector.py
│   ├── dict_attack.cpp      ← Compiled at install time
│   ├── mutation_engine.py
│   ├── hash_comparison.py
│   ├── report_gen.py
│   └── scoring.py
├── wordlists/
│   └── rockyou.txt          ← Downloaded on first install
├── reports/                 ← Audit reports go here
└── README.md
```

---

## Roadmap

- [ ] v0.1 — Alpha release, Project scaffold, CLI skeleton, argparse setup
- [ ] v0.5 — Beta release, final testing and development phase
- [ ] v1.0 — Full release, documentation, install testing on clean Linux
- [ ] v1.1 — Windows, macOS compatibility (expected)

---

## License

This project is licensed under the **GNU General Public License v3.0**.

You are free to use, modify, and distribute this tool. Any modified version must also be released under GPL v3. This ensures Mairon and all its derivatives remain open, free, and transparent — in keeping with the ethical hacking spirit it was built for.

See [LICENSE](LICENSE) for full terms.

---

## Author

Developed by Muhammad Ahmad as a CEH course project at the **NETSOL Institute of Artificial Intelligence (NIAI)**.
