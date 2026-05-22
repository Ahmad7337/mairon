import os
import datetime


def _get_reports_dir() -> str:
    path = os.path.join(os.getcwd(), "reports")
    os.makedirs(path, exist_ok=True)
    return path

def _redact(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + ("*" * (len(password) - 2)) + password[-1]


def _hr(char: str = "─", width: int = 58) -> str:
    return char * width


def _section(title: str) -> list:
    return [
        "",
        _hr(),
        f"  {title}",
        _hr(),
    ]

def generate_txt_report(password: str, results: dict, score: dict) -> str:

    timestamp  = datetime.datetime.now()
    ts_str     = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    fname      = f"mairon_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt"
    fpath      = os.path.join(_get_reports_dir(), fname)
    redacted   = _redact(password)

    lines = []

    lines += [
        _hr("═"),
        "        MAIRON — Password Audit & Analysis Report",
        _hr("═"),
        f"  Date       : {ts_str}",
        f"  Password   : {redacted}  [REDACTED]",
        f"  Score      : {score.get('score', 'N/A')}/100  —  {score.get('risk_level', 'N/A')}",
        _hr("═"),
    ]

    if "breach" in results:
        b = results["breach"]
        lines += _section("MODULE 1 — Breach Database Check")
        if b.get("error"):
            lines.append(f"  ⚠  {b['error']}")
        elif b.get("found"):
            lines += [
                f"  Status : ✗ FOUND IN BREACH DATABASE",
                f"  Count  : {b['count']:,} occurrences in known breach data",
                f"  Action : Change this password immediately.",
            ]
        else:
            lines += [
                f"  Status : ✓ Not found in breach database",
            ]

    if "entropy" in results:
        e = results["entropy"]
        lines += _section("MODULE 2 — Entropy Calculator")
        lines += [
            f"  Entropy     : {e.get('entropy', 'N/A')} bits",
            f"  Length      : {e.get('length', 'N/A')} characters",
            f"  Charset     : {e.get('charset_size', 'N/A')} possible chars",
            f"  Lowercase   : {'Yes' if e.get('has_lower') else 'No'}",
            f"  Uppercase   : {'Yes' if e.get('has_upper') else 'No'}",
            f"  Digits      : {'Yes' if e.get('has_digit')  else 'No'}",
            f"  Symbols     : {'Yes' if e.get('has_special') else 'No'}",
            f"  Rating      : {e.get('rating', 'N/A')} — {e.get('description', '')}",
        ]

    if "patterns" in results:
        p = results["patterns"]
        lines += _section("MODULE 3 — Pattern Detector")
        lines += [
            f"  Issues Found : {p.get('issue_count', 0)}",
            f"  Rating       : {p.get('rating', 'N/A')}",
        ]
        for issue in p.get("issues", []):
            lines.append(f"    → {issue}")
        if not p.get("issues"):
            lines.append("  ✓ No suspicious patterns detected.")

    if "dict_attack" in results:
        d = results["dict_attack"]
        lines += _section("MODULE 4 — Dictionary Attack Simulation")
        if d.get("error"):
            lines.append(f"  ⚠  {d['error']}")
        else:
            found = d.get("found", False)
            lines += [
                f"  Found in wordlist : {'✗ YES — password is in rockyou.txt' if found else '✓ No'}",
                f"  Words checked     : {d.get('words_checked', 0):,}",
                f"  Time taken        : {d.get('time_elapsed', 0)}s",
            ]
            if found:
                lines.append("  Action : This password would be cracked almost instantly.")

    if "mutations" in results:
        m = results["mutations"]
        lines += _section("MODULE 5 — Mutation Engine")
        lines += [
            f"  Mutations generated  : {m.get('total_mutations', 0)}",
            f"  Breached mutations   : {m.get('breached_mutations', 0)}",
            f"  Rating               : {m.get('rating', 'N/A')}",
            "",
            f"  {'Mutation':<30} {'Breached':<10} {'Count'}",
            f"  {'─' * 52}",
        ]
        for mut in m.get("mutations", [])[:20]:  # Cap at 20 in report
            status = "YES" if mut["breached"] else "No"
            count  = str(mut["breach_count"]) if mut["breached"] else "—"
            lines.append(f"  {mut['mutation']:<30} {status:<10} {count}")
        if m.get("total_mutations", 0) > 20:
            lines.append(f"  ... {m['total_mutations'] - 20} more mutations not shown.")

    if "hashes" in results:
        lines += _section("MODULE 6 — Hash Format Comparison")
        for algo, data in results["hashes"].items():
            lines += [
                f"  {algo}",
                f"    Hash     : {data['hash'][:60]}{'...' if len(data['hash']) > 60 else ''}",
                f"    Speed    : {data['gpu_speed']}",
                f"    Status   : {data['status']}",
                f"    Rating   : {data['rating']}",
                "",
            ]

    lines += _section("SCORE BREAKDOWN")
    breakdown = score.get("breakdown", {})
    name_map  = {
        "breach":     "Breach Check",
        "entropy":    "Entropy",
        "patterns":   "Pattern Detection",
        "dict_attack":"Dictionary Attack",
        "mutations":  "Mutations",
        "hashes":     "Hash Comparison",
    }
    for key, data in breakdown.items():
        deducted = data.get("deduction", 0)
        max_pts  = data.get("max", 0)
        earned   = max_pts - deducted
        lines.append(f"  {name_map.get(key, key):<22} : {earned}/{max_pts} pts")

    lines += [
        "",
        _hr("═"),
        f"  FINAL SCORE  :  {score.get('score', 'N/A')}/100",
        f"  RISK LEVEL   :  {score.get('risk_level', 'N/A')}",
        _hr("═"),
        "",
        "  Generated by Mairon v0.1.0  —  GPL v3",
        "  Developed by Muhammad Ahmad",
        "  github.com/Ahmad7337/mairon",
        "",
    ]

    with open(fpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return fpath
