import sys
import argparse

from getpass import getpass
from colorama import init, Fore, Style

from mairon.modules.breach_check    import check_breach
from mairon.modules.entropy         import calculate_entropy
from mairon.modules.pattern_detector import detect_patterns
from mairon.modules.dict_attack     import run_dict_attack
from mairon.modules.mutation_engine import analyze_mutations
from mairon.modules.hash_comparison import compare_hashes
from mairon.modules.report_gen      import generate_txt_report
from mairon.modules.scoring         import calculate_score
from mairon.utils                   import download_rockyou

BANNER = f"""
{Fore.RED}  ███╗   ███╗ █████╗ ██╗██████╗  ██████╗ ███╗   ██╗
  ████╗ ████║██╔══██╗██║██╔══██╗██╔═══██╗████╗  ██║
  ██╔████╔██║███████║██║██████╔╝██║   ██║██╔██╗ ██║
  ██║╚██╔╝██║██╔══██║██║██╔══██╗██║   ██║██║╚██╗██║
  ██║ ╚═╝ ██║██║  ██║██║██║  ██║╚██████╔╝██║ ╚████║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝{Style.RESET_ALL}
{Fore.WHITE}  Password Audit & Analysis Tool v0.1.0{Style.RESET_ALL}
{Fore.YELLOW}  Developed by Muhammad Ahmad{Style.RESET_ALL}
{Fore.CYAN}  github.com/Ahmad7337/mairon{Style.RESET_ALL}
"""

MODULE_LIST = {
    1: "Breach Database Check    (HIBP API, k-anonymity)",
    2: "Entropy Calculator       (charset analysis)",
    3: "Pattern Detector         (keyboard walks, common words, structure)",
    4: "Dictionary Attack Sim    (rockyou.txt)",
    5: "Mutation Engine          (leetspeak, suffix variants, breach check)",
    6: "Hash Format Comparison   (MD5, SHA-1, SHA-256, bcrypt)",
}

def _header(num: int, name: str) -> None:
    print(f"\n{Fore.CYAN}  {'─' * 54}")
    print(f"  [ {num} ]  {name}")
    print(f"  {'─' * 54}{Style.RESET_ALL}")

def _print_breach(result: dict) -> None:
    if result.get("error"):
        print(f"  {Fore.YELLOW}⚠  {result['error']}{Style.RESET_ALL}")
        return
    if result["found"]:
        print(f"  {Fore.RED}✗  PASSWORD FOUND IN BREACH DATABASE!{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Seen {result['count']:,} times in known breaches.{Style.RESET_ALL}")
        print(f"  {Fore.RED}   This password must be changed immediately.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓  Password not found in any known breach database.{Style.RESET_ALL}")

def _print_entropy(result: dict) -> None:
    rating = result.get("rating", "Unknown")
    color  = (
        Fore.GREEN  if rating in ("Strong", "Very Strong") else
        Fore.YELLOW if rating == "Reasonable" else
        Fore.RED
    )
    print(f"  Entropy     : {color}{result.get('entropy', 'N/A')} bits{Style.RESET_ALL}")
    print(f"  Length      : {result.get('length', 'N/A')} characters")
    print(f"  Charset     : {result.get('charset_size', 'N/A')} possible chars")
    print(f"  Lowercase   : {'Yes' if result.get('has_lower')   else Fore.YELLOW + 'No' + Style.RESET_ALL}")
    print(f"  Uppercase   : {'Yes' if result.get('has_upper')   else Fore.YELLOW + 'No' + Style.RESET_ALL}")
    print(f"  Digits      : {'Yes' if result.get('has_digit')   else Fore.YELLOW + 'No' + Style.RESET_ALL}")
    print(f"  Symbols     : {'Yes' if result.get('has_special') else Fore.YELLOW + 'No' + Style.RESET_ALL}")
    print(f"  Rating      : {color}{rating}{Style.RESET_ALL} — {result.get('description', '')}")

def _print_patterns(result: dict) -> None:
    issues = result.get("issues", [])
    rating = result.get("rating", "Unknown")
    color  = Fore.GREEN if rating == "Clean" else Fore.YELLOW if rating == "Medium Risk" else Fore.RED

    if not issues:
        print(f"  {Fore.GREEN}✓  No suspicious patterns detected.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}✗  {len(issues)} pattern(s) detected:{Style.RESET_ALL}")
        for issue in issues:
            print(f"  {Fore.RED}   →  {issue}{Style.RESET_ALL}")
    print(f"  Rating      : {color}{rating}{Style.RESET_ALL}")

def _print_dict(result: dict) -> None:
    if result.get("error"):
        print(f"  {Fore.YELLOW}⚠  {result['error']}{Style.RESET_ALL}")
        return
    if result["found"]:
        print(f"  {Fore.RED}✗  FOUND IN WORDLIST!{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Words scanned : {result['words_checked']:,}{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Time taken    : {result['time_elapsed']}s{Style.RESET_ALL}")
        print(f"  {Fore.RED}   This password would be cracked almost instantly by any attacker.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓  Password not found in wordlist.{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}   Words scanned : {result['words_checked']:,}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}   Time taken    : {result['time_elapsed']}s{Style.RESET_ALL}")

def _print_mutations(result: dict) -> None:
    mutations = result.get("mutations", [])
    breached  = result.get("breached_mutations", 0)
    rating    = result.get("rating", "Unknown")
    color     = Fore.GREEN if "Low" in rating else Fore.YELLOW if "Medium" in rating else Fore.RED

    print(f"  Mutations generated : {result.get('total_mutations', 0)}")
    b_color = Fore.RED if breached > 0 else Fore.GREEN
    print(f"  Breached mutations  : {b_color}{breached}{Style.RESET_ALL}")
    print(f"  Rating              : {color}{rating}{Style.RESET_ALL}")

    if mutations:
        print(f"\n  {Fore.WHITE}  {'Mutation':<28} {'Breached':<10} Count{Style.RESET_ALL}")
        print(f"  {'─' * 52}")
        for m in mutations[:12]:  # Show first 12
            s_color = Fore.RED if m["breached"] else Fore.GREEN
            status  = "YES" if m["breached"] else "No"
            count   = str(m["breach_count"]) if m["breached"] else "—"
            print(f"  {m['mutation']:<28} {s_color}{status:<18}{Style.RESET_ALL} {count}")
        remaining = len(mutations) - 12
        if remaining > 0:
            print(f"  {Fore.WHITE}  ... and {remaining} more (shown in report){Style.RESET_ALL}")

def _print_hashes(result: dict) -> None:
    for algo, data in result.items():
        color = (
            Fore.GREEN  if not data["crackable"] else
            Fore.YELLOW if algo == "SHA-256" else
            Fore.RED
        )
        h = data["hash"]
        print(f"\n  {Fore.WHITE}{algo}{Style.RESET_ALL}  [{color}{data['status']}{Style.RESET_ALL}]")
        print(f"    Hash     : {h[:60]}{'...' if len(h) > 60 else ''}")
        print(f"    Speed    : {data['gpu_speed']}")
        print(f"    Rating   : {color}{data['rating']}{Style.RESET_ALL}")

def _print_score(score_result: dict) -> None:
    score = score_result.get("score", 0)
    risk  = score_result.get("risk_level", "Unknown")
    color = (
        Fore.GREEN  if score >= 80 else
        Fore.YELLOW if score >= 55 else
        Fore.RED
    )

    print(f"\n{Fore.CYAN}  {'═' * 54}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}FINAL SCORE  :  {color}{score} / 100{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}RISK LEVEL   :  {color}{risk}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'═' * 54}{Style.RESET_ALL}")
    print(f"\n  {Fore.WHITE}Score breakdown:{Style.RESET_ALL}")
    name_map = {
        "breach":      "Breach Check      ",
        "entropy":     "Entropy           ",
        "patterns":    "Pattern Detection ",
        "dict_attack": "Dictionary Attack ",
        "mutations":   "Mutations         ",
        "hashes":      "Hash Comparison   ",
    }
    for key, data in score_result.get("breakdown", {}).items():
        earned   = data.get("earned", 0)
        max_pts  = data.get("max", 0)
        e_color  = Fore.GREEN if earned == max_pts else Fore.RED
        print(f"  {name_map.get(key, key)} :  {e_color}{earned:>2}/{max_pts} pts{Style.RESET_ALL}")
    print()

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mairon",
        description="Mairon — Password Audit & Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  mairon -p mypassword -a
  mairon -p mypassword -m 1,2,3
  mairon -p mypassword -a -r
  mairon -p mypassword -a --offline
  mairon --update-wordlist
  mairon --list

modules:
  1  Breach Database Check
  2  Entropy Calculator
  3  Pattern Detector
  4  Dictionary Attack Simulation
  5  Mutation Engine
  6  Hash Format Comparison
        """,
    )

    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Password to audit. Omit to be prompted securely (recommended)."
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Run all modules."
    )
    parser.add_argument(
        "-m", "--modules",
        type=str,
        metavar="MODULES",
        help="Comma-separated module numbers to run. Example: -m 1,3,5"
    )
    parser.add_argument(
        "-r", "--report",
        action="store_true",
        help="Generate a .txt report file saved to ./reports/"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip all HIBP API calls (Modules 1 and 5 breach checks). No internet required."
    )
    parser.add_argument(
        "--wordlist",
        type=str,
        metavar="PATH",
        help="Path to a custom wordlist for Module 4 (default: rockyou.txt)."
    )
    parser.add_argument(
        "--update-wordlist",
        action="store_true",
        help="Download or re-download rockyou.txt to ~/.mairon/wordlists/"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available modules and exit."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="mairon v0.1.0  —  GPL v3"
    )

    return parser

def _parse_module_list(module_str: str) -> list:
    """Parse '1,3,5' into [1, 3, 5]. Exits on invalid input."""
    try:
        modules = [int(m.strip()) for m in module_str.split(",") if m.strip()]
        invalid = [m for m in modules if m not in MODULE_LIST]
        if invalid:
            print(f"{Fore.RED}  Error: Unknown module(s): {invalid}")
            print(f"  Valid modules: {list(MODULE_LIST.keys())}{Style.RESET_ALL}")
            sys.exit(1)
        return sorted(set(modules))
    except ValueError:
        print(f"{Fore.RED}  Error: Invalid module format. Use: -m 1,3,5{Style.RESET_ALL}")
        sys.exit(1)

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    # Always show banner
    print(BANNER)

    if args.list:
        print(f"  {Fore.CYAN}Available modules:{Style.RESET_ALL}\n")
        for num, desc in MODULE_LIST.items():
            print(f"  [{num}]  {desc}")
        print()
        sys.exit(0)

    if args.update_wordlist:
        download_rockyou(force=True)
        sys.exit(0)

    if args.all:
        selected = list(MODULE_LIST.keys())   # [1, 2, 3, 4, 5, 6]
    elif args.modules:
        selected = _parse_module_list(args.modules)
    else:
        print(f"  {Fore.RED}Error: Specify modules with -m or use -a to run all.{Style.RESET_ALL}")
        print(f"  Use {Fore.WHITE}mairon --help{Style.RESET_ALL} for usage, or {Fore.WHITE}mairon --list{Style.RESET_ALL} to see all modules.\n")
        sys.exit(1)

    if args.offline:
        print(f"  {Fore.YELLOW}⚠  Offline mode: HIBP breach checks will be skipped.{Style.RESET_ALL}\n")

    if args.password:
        password = args.password
        print(
            f"  {Fore.YELLOW}⚠  Be warned: Using -p exposes the password in shell history.\n"
            f"     Consider omitting -p to use the secure prompt instead.{Style.RESET_ALL}\n"
        )
    else:
        print(f"  {Fore.WHITE}Enter the password to audit:{Style.RESET_ALL}")
        password = getpass("  Password: ")
        print()

    if not password:
        print(f"  {Fore.RED}Error: No password provided. Exiting.{Style.RESET_ALL}\n")
        sys.exit(1)

    results = {}

    if 1 in selected:
        _header(1, "Breach Database Check")
        if args.offline:
            print(f"  {Fore.YELLOW}Skipped (offline mode){Style.RESET_ALL}")
        else:
            r = check_breach(password)
            results["breach"] = r
            _print_breach(r)

    if 2 in selected:
        _header(2, "Entropy Calculator")
        r = calculate_entropy(password)
        results["entropy"] = r
        _print_entropy(r)

    if 3 in selected:
        _header(3, "Pattern Detector")
        r = detect_patterns(password)
        results["patterns"] = r
        _print_patterns(r)

    if 4 in selected:
        _header(4, "Dictionary Attack Simulation")
        print(f"  {Fore.WHITE}Scanning wordlist — this may take up to a minute...{Style.RESET_ALL}")
        r = run_dict_attack(password, args.wordlist)
        results["dict_attack"] = r
        _print_dict(r)

    if 5 in selected:
        _header(5, "Mutation Engine")
        if not args.offline:
            print(f"  {Fore.WHITE}Checking mutations against breach database...{Style.RESET_ALL}")
        r = analyze_mutations(password, offline=args.offline)
        results["mutations"] = r
        _print_mutations(r)

    if 6 in selected:
        _header(6, "Hash Format Comparison")
        r = compare_hashes(password)
        results["hashes"] = r
        _print_hashes(r)

    if results:
        score_result = calculate_score(results)
        _print_score(score_result)

        if args.report:
            print(f"  {Fore.CYAN}Generating report...{Style.RESET_ALL}")
            path = generate_txt_report(password, results, score_result)
            print(f"  {Fore.GREEN}✓  Report saved to: {path}{Style.RESET_ALL}\n")
    else:
        print(f"  {Fore.YELLOW}No modules produced results. Nothing to score.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
