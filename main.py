"""
main.py — Windows Service & Process Monitoring Agent  (v3.0)
=============================================================
Entry point. Orchestrates enumeration, analysis, alerting, and reporting.

Usage:
    python main.py                            # single scan + report
    python main.py --watch 30                 # real-time loop every 30 s
    python main.py --watch 30 --dashboard     # rich live dashboard
    python main.py --tree                     # annotated process tree
    python main.py --signatures               # verify Authenticode signatures
    python main.py --kill                     # auto-terminate HIGH threats
    python main.py --kill --kill-dry-run      # show what WOULD be killed
    python main.py --baseline                 # save system baseline then exit
    python main.py --compare                  # diff current state vs baseline

Recommended: run as Administrator for full process and service visibility.
"""

import argparse
import atexit
import json
import os
import sys
import time
import socket
import datetime

# ── Rich (dashboard + kill confirmation table) ────────────────────────────
from rich.console    import Console
from rich.table      import Table
from rich.panel      import Panel
from rich.layout     import Layout
from rich.live       import Live
from rich.text       import Text
from rich.rule       import Rule
from rich.align      import Align
from rich            import box

# ── Colorama (plain-text colored output) ─────────────────────────────────
from colorama import init as colorama_init, Fore, Style

from modules.alert_engine      import (
    Alert, AlertEngine,
    SEVERITY_MALICIOUS, SEVERITY_SUSPICIOUS, SEVERITY_LOW, SEVERITY_SYSTEM,
    SEVERITY_HIGH, SEVERITY_MEDIUM,   # backward-compat aliases
    CATEGORY_SERVICE, CATEGORY_UNAUTHORIZED, CATEGORY_UNKNOWN,
    CATEGORY_INCOMPLETE_DATA,
)
from modules.process_monitor   import ProcessMonitor
from modules.service_auditor   import ServiceAuditor
from modules.process_detector  import ProcessDetector
from modules.response_engine   import ResponseEngine
from modules.baseline_manager  import BaselineManager
from reporting.logger          import MonitorLogger
from reporting.report_generator import ReportGenerator

console = Console()


# ─────────────────────────────────────────────────────────────────────────
# Config helpers
# ─────────────────────────────────────────────────────────────────────────

def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_configs(config_dir: str) -> tuple:
    whitelist_data = load_json(os.path.join(config_dir, "whitelist.json"))
    blacklist_data = load_json(os.path.join(config_dir, "blacklist.json"))
    rules          = load_json(os.path.join(config_dir, "rules.json"))
    hashes_path    = os.path.join(config_dir, "known_bad_hashes.json")
    hashes_data    = load_json(hashes_path) if os.path.exists(hashes_path) else {}
    return (
        whitelist_data.get("processes", []),
        blacklist_data.get("processes", []),
        blacklist_data.get("name_patterns", []),
        rules,
        hashes_data.get("sha256", []),
        hashes_data.get("md5", []),
    )


# ─────────────────────────────────────────────────────────────────────────
# Core scan
# ─────────────────────────────────────────────────────────────────────────

def run_scan(
    whitelist, blacklist, blacklist_patterns, rules,
    bad_sha256, bad_md5, verify_signatures: bool,
):
    """Run one complete detection cycle. Returns (engine, processes, services, anomalous_pids, tree)."""
    engine   = AlertEngine()
    monitor  = ProcessMonitor()
    auditor  = ServiceAuditor()
    detector = ProcessDetector()

    processes = monitor.enumerate_processes()
    tree      = monitor.build_process_tree(processes)
    anomalous = monitor.detect_parent_child_anomalies(processes, rules, engine)

    services = auditor.enumerate_services()
    auditor.audit_services(services, rules, engine, verify_signatures=verify_signatures)

    detector.detect_unauthorized(
        processes, whitelist, blacklist, blacklist_patterns, rules, engine,
        bad_hashes_sha256=bad_sha256,
        bad_hashes_md5=bad_md5,
        verify_signatures=verify_signatures,
    )

    return engine, processes, services, anomalous, tree


# ─────────────────────────────────────────────────────────────────────────
# Feature B helpers — baseline alert injection
# ─────────────────────────────────────────────────────────────────────────

def _inject_baseline_alerts(
    engine: AlertEngine,
    diff_procs: dict,
    diff_svcs: dict,
    rules: dict,
) -> int:
    """
    Translate BaselineManager diffs into Alert objects and add them to the engine.
    Returns the total number of new alerts injected.
    """
    cat_mitre   = rules.get("category_mitre", {})
    svc_mitre   = cat_mitre.get("SERVICE",      {})
    unauth_mitre = cat_mitre.get("UNAUTHORIZED", {})
    path_mitre  = {"id": "T1574.009", "name": "Path Interception by Unquoted Path",
                   "tactic": "Privilege Escalation"}
    injected = 0

    # ── New processes ─────────────────────────────────────────────────────
    for proc in diff_procs.get("new", []):
        engine.add(Alert(
            severity=SEVERITY_SUSPICIOUS,
            category=CATEGORY_UNAUTHORIZED,
            description=f"[BASELINE] New process appeared since baseline: {proc.get('name', '?')}",
            pid=proc.get("pid"),
            process_name=proc.get("name"),
            exe_path=proc.get("exe"),
            mitre_id=unauth_mitre.get("id"),
            mitre_name=unauth_mitre.get("name"),
            mitre_tactic=unauth_mitre.get("tactic"),
            details={
                "detection_type": "baseline_new_process",
                "exe":            proc.get("exe", ""),
                "username":       proc.get("username", ""),
            },
        ))
        injected += 1

    # ── New services ──────────────────────────────────────────────────────
    for svc in diff_svcs.get("new", []):
        is_autostart = svc.get("start_mode", "").lower() in ("auto", "automatic")
        severity     = SEVERITY_MALICIOUS if is_autostart else SEVERITY_SUSPICIOUS
        engine.add(Alert(
            severity=severity,
            category=CATEGORY_SERVICE,
            description=(
                f"[BASELINE] New {'auto-start ' if is_autostart else ''}service "
                f"registered since baseline: {svc.get('name', '?')}"
            ),
            process_name=svc.get("name"),
            exe_path=svc.get("path"),
            mitre_id=svc_mitre.get("id"),
            mitre_name=svc_mitre.get("name"),
            mitre_tactic=svc_mitre.get("tactic"),
            details={
                "detection_type": "baseline_new_service",
                "display_name":   svc.get("display_name", ""),
                "path":           svc.get("path", ""),
                "start_mode":     svc.get("start_mode", ""),
                "start_name":     svc.get("start_name", ""),
            },
        ))
        injected += 1

    # ── Changed services ──────────────────────────────────────────────────
    for change in diff_svcs.get("changed", []):
        field    = change.get("field", "")
        severity = SEVERITY_MALICIOUS if field == "path" else SEVERITY_SUSPICIOUS
        mitre    = path_mitre if field == "path" else svc_mitre
        engine.add(Alert(
            severity=severity,
            category=CATEGORY_SERVICE,
            description=(
                f"[BASELINE] Service '{change.get('name', '?')}' changed field "
                f"'{field}': '{change.get('old', '')}' -> '{change.get('new', '')}'"
            ),
            process_name=change.get("name"),
            mitre_id=mitre.get("id"),
            mitre_name=mitre.get("name"),
            mitre_tactic=mitre.get("tactic"),
            details={
                "detection_type": "baseline_changed_service",
                "display_name":   change.get("display_name", ""),
                "changed_field":  field,
                "old_value":      change.get("old", ""),
                "new_value":      change.get("new", ""),
            },
        ))
        injected += 1

    return injected


# ─────────────────────────────────────────────────────────────────────────
# Feature A helpers — kill phase
# ─────────────────────────────────────────────────────────────────────────

def _run_kill_phase(
    engine: AlertEngine,
    args,
    logger: MonitorLogger,
    use_color: bool,
) -> None:
    """
    Show killable targets, prompt for confirmation (unless --kill-force),
    then call ResponseEngine.kill_high_alerts().
    """
    re   = ResponseEngine(logger=logger)
    targets = re.get_killable_alerts(engine.get_all())

    if not targets:
        print_section("AUTO-RESPONSE - KILL", Fore.GREEN)
        print("  No killable HIGH-severity targets found.")
        return

    print_section(
        "AUTO-RESPONSE - KILL  (dry-run)" if args.kill_dry_run else "AUTO-RESPONSE - KILL",
        Fore.RED,
    )

    # Build a rich confirmation table
    kill_table = Table(box=box.SIMPLE_HEAVY, header_style="bold red", expand=False)
    kill_table.add_column("Score",    width=6,  justify="center")
    kill_table.add_column("Category", width=15)
    kill_table.add_column("PID",      width=7,  justify="right")
    kill_table.add_column("Process",  width=22)
    kill_table.add_column("Path",     ratio=1)

    for a in targets:
        kill_table.add_row(
            Text(str(a.score), style="bold red"),
            a.category,
            str(a.pid),
            a.process_name or "N/A",
            (a.exe_path or "N/A")[:70],
        )

    console.print(kill_table)

    # Dry-run: show only, do not act
    if args.kill_dry_run:
        console.print(
            f"[bold yellow]DRY-RUN:[/bold yellow] {len(targets)} process(es) would be terminated."
        )
        return

    # Confirmation prompt
    if not args.kill_force:
        try:
            answer = input(
                f"\n  Terminate {len(targets)} process(es) listed above? [y/N]: "
            ).strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print("  Kill aborted by user.")
            logger.log_info("Kill phase aborted by user confirmation prompt")
            return

    # Execute kills
    results = re.kill_high_alerts(engine.get_all(), dry_run=False)
    summary = re.summary(results)

    print(f"\n  Kill results:")
    print(f"    Attempted : {summary['attempted']}")
    c_ok  = (Fore.GREEN + Style.BRIGHT) if use_color else ""
    c_bad = (Fore.RED   + Style.BRIGHT) if use_color else ""
    reset = Style.RESET_ALL if use_color else ""
    print(f"    Succeeded : {c_ok}{summary['succeeded']}{reset}")
    print(f"    Failed    : {c_bad}{summary['failed']}{reset}")
    print(f"    Still alive (may need elevation): {summary['still_alive']}")


# ─────────────────────────────────────────────────────────────────────────
# Rich dashboard builder
# ─────────────────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    SEVERITY_MALICIOUS:  "bold red",
    SEVERITY_SUSPICIOUS: "bold yellow",
    SEVERITY_LOW:        "bold cyan",
    SEVERITY_SYSTEM:     "dim white",
}


def build_dashboard(
    engine: AlertEngine,
    processes: list[dict],
    services: list[dict],
    scan_num: int,
    next_scan_in: int,
    new_count: int,
    baseline_mode: bool = False,
) -> Layout:
    stats    = engine.summary_stats()
    by_sev   = stats["by_severity"]
    hostname = socket.gethostname()
    now_str  = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body",   ratio=1),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left",  ratio=2),
        Layout(name="right", ratio=3),
    )
    layout["left"].split_column(
        Layout(name="summary", ratio=1),
        Layout(name="system",  size=11),
    )

    # Header
    header_text = Text(justify="center")
    header_text.append("  Windows Service & Process Monitoring Agent  ", style="bold white on blue")
    header_text.append(f"  Scan #{scan_num}  ", style="bold cyan")
    header_text.append(f"  {now_str}  ", style="dim")
    layout["header"].update(Panel(Align.center(header_text), style="blue"))

    # Summary
    summary_table = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count",    justify="right")
    summary_table.add_column("Bar",      no_wrap=True)
    for sev, style in [
        (SEVERITY_MALICIOUS,  "bold red"),
        (SEVERITY_SUSPICIOUS, "bold yellow"),
        (SEVERITY_LOW,        "bold cyan"),
    ]:
        cnt = by_sev.get(sev, 0)
        bar = "\u2588" * min(cnt, 15) + "\u2591" * (15 - min(cnt, 15))
        summary_table.add_row(Text(sev, style=style), Text(str(cnt), style=style), Text(bar, style=style))
    score = stats.get("score", {})
    layout["summary"].update(Panel(
        summary_table,
        title=f"[bold]ALERT SUMMARY[/bold]  (total: {stats['total']})",
        border_style="red" if by_sev.get(SEVERITY_HIGH, 0) > 0 else "yellow",
    ))

    # System status
    baseline_line = f"[dim]Mode      :[/dim]  [bold cyan]BASELINE COMPARE[/bold cyan]" if baseline_mode else "[dim]Mode      :[/dim]  Standard"
    by_cat      = stats.get("by_category", {})
    incomplete  = by_cat.get(CATEGORY_INCOMPLETE_DATA, 0)
    unknown_cnt = by_cat.get(CATEGORY_UNKNOWN, 0)
    sys_lines = [
        baseline_line,
        f"[dim]Host        :[/dim]  {hostname}",
        f"[dim]Processes   :[/dim]  {len(processes)}",
        f"[dim]Services    :[/dim]  {len(services)}",
        f"[dim]No-exe-path :[/dim]  [yellow]{incomplete}[/yellow]  (access-denied / hollow suspect)",
        f"[dim]Unknown     :[/dim]  [cyan]{unknown_cnt}[/cyan]  unique unlisted names",
        f"[dim]Max Score   :[/dim]  [bold]{score.get('max', 0)}/100[/bold]",
        f"[dim]Avg Score   :[/dim]  {score.get('average', 0)}/100",
        f"[dim]Next scan   :[/dim]  [bold cyan]{next_scan_in}s[/bold cyan]",
        f"[dim]New alerts  :[/dim]  [bold yellow]{new_count}[/bold yellow]",
    ]
    layout["system"].update(Panel("\n".join(sys_lines), title="[bold]SYSTEM STATUS[/bold]", border_style="blue"))

    # Top alerts
    top_alerts = engine.top_alerts(n=15)
    alerts_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white", expand=True)
    alerts_table.add_column("Score",       width=6,  justify="center")
    alerts_table.add_column("Sev",         width=7)
    alerts_table.add_column("Conf",        width=7)
    alerts_table.add_column("Cat",         width=16)
    alerts_table.add_column("PID",         width=7,  justify="right")
    alerts_table.add_column("Process",     width=18, no_wrap=True)
    alerts_table.add_column("MITRE",       width=10)
    alerts_table.add_column("Description", ratio=1)

    _CONF_STYLE = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "dim cyan"}
    for a in top_alerts:
        style     = SEVERITY_STYLE.get(a.severity, "white")
        conf      = getattr(a, "confidence", "")
        conf_sty  = _CONF_STYLE.get(conf, "white")
        desc      = a.description[:52] + "..." if len(a.description) > 55 else a.description
        alerts_table.add_row(
            Text(str(a.score), style=style), Text(a.severity, style=style),
            Text(conf, style=conf_sty),
            a.category, str(a.pid or "-"), a.process_name or "-",
            a.mitre_id or "-", desc,
        )
    layout["right"].update(Panel(
        alerts_table,
        title="[bold]TOP ALERTS BY RISK SCORE[/bold]",
        border_style="red" if top_alerts and top_alerts[0].severity == SEVERITY_HIGH else "yellow",
    ))

    # MITRE footer
    mitre_ids = sorted({a.mitre_id for a in engine.get_all() if a.mitre_id})
    mitre_str = "  ".join(f"[bold cyan]{m}[/bold cyan]" for m in mitre_ids) or "[dim]No MITRE-mapped alerts[/dim]"
    layout["footer"].update(Panel(mitre_str, title="[bold]MITRE ATT&CK TECHNIQUES OBSERVED[/bold]", border_style="cyan"))

    return layout


# ─────────────────────────────────────────────────────────────────────────
# Plain-mode helpers
# ─────────────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    SEVERITY_MALICIOUS:  Fore.RED,
    SEVERITY_SUSPICIOUS: Fore.YELLOW,
    SEVERITY_LOW:        Fore.CYAN,
    SEVERITY_SYSTEM:     Fore.WHITE,
}


def print_section(title: str, color=Fore.WHITE):
    print(f"\n{color}{Style.BRIGHT}{'-' * 68}")
    print(f"  {title}")
    print(f"{'-' * 68}{Style.RESET_ALL}")


def print_alert_plain(alert, use_color: bool = True, timeline: dict = None):
    color = SEVERITY_COLOR.get(alert.severity, Fore.WHITE) if use_color else ""
    reset = Style.RESET_ALL if use_color else ""
    tag   = "[!]" if alert.severity == SEVERITY_HIGH else "[~]"
    conf  = getattr(alert, "confidence", "")
    conf_str = f" [Conf:{conf}]" if conf else ""
    print(f"{color}  {tag} [{alert.severity}] [Score:{alert.score}/100]{conf_str} "
          f"{alert.category} | {alert.description}{reset}")
    if alert.pid:
        print(f"       PID     : {alert.pid}  Process: {alert.process_name or 'N/A'}")
    if getattr(alert, "reason_code", ""):
        print(f"       Reason  : {alert.reason_code}")
    if alert.exe_path:
        print(f"       Path    : {alert.exe_path}")
    if alert.mitre_id:
        print(f"       MITRE   : {alert.mitre_id} — {alert.mitre_name}")
    if timeline and timeline.get("count", 1) > 1:
        print(
            f"       Timeline: first={timeline['first_seen']}  "
            f"last={timeline['last_seen']}  "
            f"seen={timeline['count']}×"
        )


def banner_plain(use_color: bool):
    if use_color:
        print(Fore.CYAN + Style.BRIGHT + r"""
 __      _____ _  _   __  __  ___  _  _
 \ \    / /_ _| \| | |  \/  |/ _ \| \| |
  \ \/\/ / | || .` | | |\/| | (_) | .` |
   \_/\_/ |___|_|\_| |_|  |_|\___/|_|\_|
""" + Style.RESET_ALL)
    print("  Windows Service & Process Monitoring Agent  |  v3.0  |  Blue Team\n")


# ─────────────────────────────────────────────────────────────────────────
# Single scan
# ─────────────────────────────────────────────────────────────────────────

def do_single_scan(args, whitelist, blacklist, blacklist_patterns,
                   rules, bad_sha256, bad_md5, use_color: bool):
    logger   = MonitorLogger(log_dir=args.log_dir)
    reporter = ReportGenerator(report_dir=args.report_dir)
    monitor  = ProcessMonitor()
    bm       = BaselineManager()

    print_section("STEP 1 - Enumerating Processes & Services", Fore.CYAN)
    engine, processes, services, anomalous, tree = run_scan(
        whitelist, blacklist, blacklist_patterns, rules,
        bad_sha256, bad_md5, args.signatures,
    )
    print(f"  Captured {len(processes)} processes, {len(services)} services.")

    # ── Feature B: Save baseline then exit ───────────────────────────────
    if args.baseline:
        saved_path = bm.save(processes, services, path=args.baseline_path)
        print_section("BASELINE SAVED", Fore.GREEN)
        print(f"  Snapshot written to: {saved_path}")
        print(f"  Processes captured : {len(processes)}")
        print(f"  Services  captured : {len(services)}")
        print(f"\n  Run with --compare on future scans to detect drift.\n")
        logger.log_info("Baseline saved", extra={"path": saved_path,
                         "processes": len(processes), "services": len(services)})
        logger.close()
        return

    # ── Feature B: Compare against baseline ──────────────────────────────
    baseline_injected = 0
    if args.compare:
        print_section("BASELINE COMPARISON", Fore.CYAN)
        data = bm.load(path=args.baseline_path)
        if data is None:
            print(f"  No baseline found at '{args.baseline_path}'.")
            print("  Run with --baseline first to create one.\n")
            logger.log_info("Baseline compare skipped: no baseline file found")
        else:
            meta = data.get("metadata", {})
            print(f"  Baseline created : {meta.get('created_at', 'unknown')}")
            print(f"  Baseline host    : {meta.get('hostname', 'unknown')}")
            dp = bm.compare_processes(processes, data)
            ds = bm.compare_services(services, data)
            baseline_injected = _inject_baseline_alerts(engine, dp, ds, rules)
            print(f"  New processes since baseline  : {len(dp['new'])}")
            print(f"  Missing processes             : {len(dp['missing'])}")
            print(f"  New services since baseline   : {len(ds['new'])}")
            print(f"  Changed service configs       : {len(ds['changed'])}")
            print(f"  Baseline diff alerts injected : {baseline_injected}")
            logger.log_info("Baseline compare done", extra={
                "new_procs": len(dp["new"]), "missing_procs": len(dp["missing"]),
                "new_svcs":  len(ds["new"]), "changed_svcs":  len(ds["changed"]),
                "injected":  baseline_injected,
            })

    # Process tree
    if args.tree:
        print_section("PROCESS TREE (annotated)", Fore.CYAN)
        for line in monitor.render_process_tree(tree, anomalous_pids=anomalous):
            if "<< [!ALERT!]" in line:
                print(f"{Fore.RED if use_color else ''}{line}{Style.RESET_ALL if use_color else ''}")
            else:
                print("  " + line)

    print_section("STEP 2 - Parent-Child Anomalies", Fore.CYAN)
    pc = engine.get_by_category("PARENT_CHILD")
    print(f"  Found: {len(pc)}")
    for a in pc:
        print_alert_plain(a, use_color)

    print_section("STEP 3 - Service Audit", Fore.CYAN)
    svc_alerts = engine.get_by_category("SERVICE")
    print(f"  Found: {len(svc_alerts)}")
    for a in svc_alerts:
        print_alert_plain(a, use_color)

    print_section("STEP 4 - Threat Detection Results", Fore.CYAN)

    # Tier 1 — MALICIOUS: confirmed / near-confirmed threats (score 80–100)
    malicious_alerts = (
        engine.get_by_category("BLACKLIST")
        + engine.get_by_category("HASH_MATCH")
        + engine.get_by_category("UNAUTHORIZED")
    )
    print(f"  [MALICIOUS]  Confirmed threats       : {len(malicious_alerts)}"
          f"  (score 80–100)")
    for a in malicious_alerts:
        print_alert_plain(a, use_color)

    # Tier 2 — SUSPICIOUS: behavioral indicators (score 40–70)
    # NOTE: PARENT_CHILD already shown in STEP 2 above — excluded here to
    # avoid duplicate output.  Counts in summary_stats() still include them.
    suspicious_alerts = (
        engine.get_by_category("TYPOSQUAT")
        + engine.get_by_category("SUSPICIOUS_PATH")
        + engine.get_by_category(CATEGORY_INCOMPLETE_DATA)
    )
    if suspicious_alerts:
        print(f"\n  [SUSPICIOUS] Behavioral indicators  : {len(suspicious_alerts)}"
              f"  (score 40–70)")
        for a in suspicious_alerts:
            print_alert_plain(a, use_color)

    # Tier 3 — LOW: unknown outside trusted dirs (score 10–30, informational)
    # Deduplicated and grouped: same binary running as multiple instances
    # is shown once with a note so the output stays analyst-readable.
    grouped_unknowns = engine.get_grouped_unknowns()
    c_low  = (Fore.CYAN + Style.BRIGHT) if use_color else ""
    c_dim  = (Fore.WHITE + Style.DIM)   if use_color else ""
    reset  = Style.RESET_ALL            if use_color else ""
    print(f"\n  [LOW]        Unknown processes (outside standard dirs) : "
          f"{len(grouped_unknowns)} unique  (score 10–30 — review periodically)")
    if grouped_unknowns:
        shown = grouped_unknowns[:15]   # cap at 15 in console; full list in report
        for entry in shown:
            a     = entry["alert"]
            cnt   = entry["count"]
            multi = f"  ×{cnt}" if cnt > 1 else ""
            path  = (a.exe_path or "no path")[:60]
            print(f"{c_low}    [{a.score:2d}] {(a.process_name or 'N/A'):<28}{multi}{reset}"
                  f"{c_dim}  {path}{reset}")
        remainder = len(grouped_unknowns) - len(shown)
        if remainder > 0:
            print(f"{c_dim}    ... and {remainder} more — see JSON report for full list{reset}")

    # ── Feature A: Kill phase ─────────────────────────────────────────────
    if args.kill or args.kill_dry_run:
        _run_kill_phase(engine, args, logger, use_color)

    print_section("STEP 5 - Logging & Reporting", Fore.CYAN)
    for alert in engine.get_all():
        logger.log_alert(alert)
    print(f"  Log  -> {logger.log_path}")
    txt_path, json_path = reporter.generate(engine.get_all(), engine.summary_stats())
    print(f"  TXT  -> {txt_path}")
    print(f"  JSON -> {json_path}")
    logger.close()

    _print_final_summary(engine, use_color)


# ─────────────────────────────────────────────────────────────────────────
# Real-time watch loop
# ─────────────────────────────────────────────────────────────────────────

def do_watch_loop(args, whitelist, blacklist, blacklist_patterns,
                  rules, bad_sha256, bad_md5, use_color: bool):
    interval  = args.watch
    dashboard = args.dashboard
    logger    = MonitorLogger(log_dir=args.log_dir)
    atexit.register(logger.close)   # flush log on Ctrl+C / sys.exit()
    reporter  = ReportGenerator(report_dir=args.report_dir)
    monitor   = ProcessMonitor()
    bm        = BaselineManager()

    # Warn: --kill in watch mode skips interactive prompt
    if args.kill and not args.kill_force:
        console.print(
            "[bold yellow]WARNING:[/bold yellow] --kill in watch mode implies --kill-force "
            "(cannot prompt in a loop). Kills will execute automatically."
        )
        args.kill_force = True

    # Load baseline once before the loop (compare against a fixed snapshot)
    baseline_data = None
    if args.compare:
        baseline_data = bm.load(path=args.baseline_path)
        if baseline_data is None:
            console.print(
                f"[bold yellow]WARNING:[/bold yellow] No baseline at '{args.baseline_path}'. "
                "Run with --baseline first. Continuing without comparison."
            )

    known_fingerprints: set = set()
    scan_num = 0

    # ── Alert timeline tracker (persists across all scan iterations) ──────
    # Tracks first_seen / last_seen / count per alert fingerprint.
    # Mimics SIEM event-timeline behavior: same detection recurring over
    # multiple scans is counted rather than re-reported from scratch.
    _timeline: dict[str, dict] = {}  # fp → {first_seen, last_seen, count}

    if dashboard:
        console.print(Rule("[bold cyan]Starting real-time monitor - press Ctrl+C to stop[/bold cyan]"))
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                scan_num += 1
                engine, processes, services, anomalous, tree = run_scan(
                    whitelist, blacklist, blacklist_patterns, rules,
                    bad_sha256, bad_md5, args.signatures,
                )

                if baseline_data is not None:
                    dp = bm.compare_processes(processes, baseline_data)
                    ds = bm.compare_services(services, baseline_data)
                    _inject_baseline_alerts(engine, dp, ds, rules)

                if args.kill or args.kill_dry_run:
                    re_eng = ResponseEngine(logger=logger)
                    re_eng.kill_high_alerts(engine.get_all(), dry_run=args.kill_dry_run)

                new_alerts = engine.get_new_since(known_fingerprints)
                for a in new_alerts:
                    logger.log_alert(a)
                known_fingerprints = engine.all_fingerprints()

                # Update timeline for every alert in this scan
                _now = datetime.datetime.now().strftime("%H:%M:%S")
                for a in engine.get_all():
                    fp = a.fingerprint
                    if fp in _timeline:
                        _timeline[fp]["last_seen"] = _now
                        _timeline[fp]["count"]    += 1
                    else:
                        _timeline[fp] = {"first_seen": _now, "last_seen": _now, "count": 1}

                for remaining in range(interval, 0, -1):
                    layout = build_dashboard(
                        engine, processes, services,
                        scan_num, remaining, len(new_alerts),
                        baseline_mode=(baseline_data is not None),
                    )
                    live.update(layout)
                    time.sleep(1)

                reporter.generate(engine.get_all(), engine.summary_stats())

    else:
        console.print(f"[cyan]Real-time mode: scanning every {interval}s. Ctrl+C to stop.[/cyan]\n")
        while True:
            scan_num += 1
            print_section(
                f"SCAN #{scan_num} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                Fore.CYAN,
            )
            engine, processes, services, anomalous, tree = run_scan(
                whitelist, blacklist, blacklist_patterns, rules,
                bad_sha256, bad_md5, args.signatures,
            )

            if baseline_data is not None:
                dp = bm.compare_processes(processes, baseline_data)
                ds = bm.compare_services(services, baseline_data)
                injected = _inject_baseline_alerts(engine, dp, ds, rules)
                if injected:
                    print(f"  Baseline diff: {injected} new alert(s) injected")

            new_alerts = engine.get_new_since(known_fingerprints)
            print(f"  Processes: {len(processes)}  |  Services: {len(services)}")
            print(f"  Total alerts: {engine.summary_stats()['total']} | New this scan: {len(new_alerts)}")

            # Update timeline for all alerts in this scan
            _now = datetime.datetime.now().strftime("%H:%M:%S")
            for a in engine.get_all():
                fp = a.fingerprint
                if fp in _timeline:
                    _timeline[fp]["last_seen"] = _now
                    _timeline[fp]["count"]    += 1
                else:
                    _timeline[fp] = {"first_seen": _now, "last_seen": _now, "count": 1}

            for a in new_alerts:
                logger.log_alert(a)
                print_alert_plain(a, use_color, timeline=_timeline.get(a.fingerprint))

            known_fingerprints = engine.all_fingerprints()

            if args.kill or args.kill_dry_run:
                _run_kill_phase(engine, args, logger, use_color)

            if args.tree:
                print_section("PROCESS TREE", Fore.CYAN)
                for line in monitor.render_process_tree(tree, anomalous_pids=anomalous):
                    if "<< [!ALERT!]" in line:
                        print(f"{Fore.RED if use_color else ''}{line}{Style.RESET_ALL if use_color else ''}")
                    else:
                        print("  " + line)

            print(f"\n  [Next scan in {interval}s - Ctrl+C to stop]\n")
            time.sleep(interval)

    logger.close()


# ─────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────

def _print_final_summary(engine: AlertEngine, use_color: bool):
    stats  = engine.summary_stats()
    by_sev = stats["by_severity"]
    score  = stats.get("score", {})

    malicious       = by_sev.get(SEVERITY_MALICIOUS,  0)
    suspicious      = by_sev.get(SEVERITY_SUSPICIOUS, 0)
    low             = by_sev.get(SEVERITY_LOW,        0)
    unknown         = stats["by_category"].get(CATEGORY_UNKNOWN,         0)
    incomplete_data = stats["by_category"].get(CATEGORY_INCOMPLETE_DATA, 0)
    risk       = (
        "CRITICAL" if malicious  >= 5 else
        "HIGH"     if malicious  >= 2 else
        "ELEVATED" if suspicious >= 5 else
        "MODERATE" if suspicious >= 1 else "LOW"
    )

    c_mal = (Fore.RED    + Style.BRIGHT) if use_color else ""
    c_sus = (Fore.YELLOW + Style.BRIGHT) if use_color else ""
    c_low = (Fore.CYAN   + Style.BRIGHT) if use_color else ""
    c_dim = (Fore.WHITE  + Style.DIM)    if use_color else ""
    c_r   = ((Fore.RED if malicious > 0 else Fore.GREEN) + Style.BRIGHT) if use_color else ""
    reset = Style.RESET_ALL if use_color else ""

    print_section("SCAN COMPLETE - SUMMARY", Fore.GREEN if malicious == 0 else Fore.RED)
    print(f"  Risk Level    : {c_r}{risk}{reset}")
    print(f"  Total Alerts  : {stats['total']}")
    print(f"  {c_mal}MALICIOUS       : {malicious:>3}   score 80–100  confirmed / near-confirmed threats{reset}")
    print(f"  {c_sus}SUSPICIOUS      : {suspicious:>3}   score 40–70   behavioral indicators, investigate{reset}")
    print(f"  {c_sus}  └ no-exe-path : {incomplete_data:>3}   (subset of SUSPICIOUS — access-denied or hollow suspect){reset}")
    print(f"  {c_low}LOW             : {low:>3}   score 10–30   unknown outside trusted dirs{reset}")
    print(f"  {c_dim}  └ UNKNOWN     : {unknown:>3}   (subset of LOW — unlisted unique process names){reset}")
    print(f"  Max Score     : {score.get('max', 0)}/100")
    print(f"  Avg Score     : {score.get('average', 0)}/100")

    mitre_ids = sorted({a.mitre_id for a in engine.get_all() if a.mitre_id})
    if mitre_ids:
        print("\n  MITRE ATT&CK Techniques Observed:")
        for mid in mitre_ids:
            a = next(x for x in engine.get_all() if x.mitre_id == mid)
            print(f"    {mid:<12} {a.mitre_name or ''}")
    print()


# ─────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Windows Service & Process Monitoring Agent v3.0",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Core options
    parser.add_argument("--report-dir",  default="reports",  help="Output dir for report files")
    parser.add_argument("--log-dir",     default="logs",     help="Output dir for JSONL log files")
    parser.add_argument("--config-dir",  default="config",   help="Dir with JSON config files")
    parser.add_argument("--no-color",    action="store_true", help="Disable colored output")
    parser.add_argument("--tree",        action="store_true", help="Print annotated process tree")
    parser.add_argument("--signatures",  action="store_true", help="Verify Authenticode signatures (slow)")
    parser.add_argument("--watch",       type=int, default=0, metavar="SECONDS",
                        help="Real-time loop: scan every N seconds")
    parser.add_argument("--dashboard",   action="store_true",
                        help="Show rich live dashboard (use with --watch)")

    # Feature A — Kill
    parser.add_argument("--kill",         action="store_true",
                        help="Auto-terminate HIGH-severity processes after scan")
    parser.add_argument("--kill-dry-run", action="store_true",
                        help="Show what --kill would terminate without acting")
    parser.add_argument("--kill-force",   action="store_true",
                        help="Skip y/N confirmation before killing")

    # Feature B — Baseline
    parser.add_argument("--baseline",      action="store_true",
                        help="Save current system state as baseline then exit")
    parser.add_argument("--compare",       action="store_true",
                        help="Compare current scan against saved baseline")
    parser.add_argument("--baseline-path", default="baseline/baseline.json",
                        metavar="PATH",
                        help="Path for baseline.json (default: baseline/baseline.json)")

    args = parser.parse_args()

    use_color = not args.no_color
    colorama_init(autoreset=True)

    # Guard: --baseline inside --watch makes no sense
    if args.baseline and args.watch > 0:
        console.print("[bold red]ERROR:[/bold red] --baseline cannot be used with --watch.")
        console.print("  Run without --watch to save a baseline snapshot, then use --compare in watch mode.")
        sys.exit(1)

    if not args.dashboard:
        banner_plain(use_color)

    try:
        whitelist, blacklist, blacklist_patterns, rules, bad_sha256, bad_md5 = \
            load_configs(args.config_dir)
    except FileNotFoundError as e:
        console.print(f"[bold red]ERROR:[/bold red] Config file not found: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ERROR:[/bold red] Invalid JSON in config: {e}")
        sys.exit(1)

    try:
        if args.watch > 0:
            do_watch_loop(
                args, whitelist, blacklist, blacklist_patterns,
                rules, bad_sha256, bad_md5, use_color,
            )
        else:
            do_single_scan(
                args, whitelist, blacklist, blacklist_patterns,
                rules, bad_sha256, bad_md5, use_color,
            )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW if use_color else ''}  [Stopped by user]{Style.RESET_ALL if use_color else ''}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
