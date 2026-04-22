"""
trigger_test.py — Guaranteed detection demo for the Windows monitoring agent.

HOW TO USE (2 terminals):
  Terminal 1:  python tests/trigger_test.py
  Terminal 2:  python main.py --watch 5 --dashboard
               (or: python main.py --signatures)

The script plants 4 live triggers, prints a countdown, then auto-cleans up.
All planted files are renamed copies of cmd.exe — zero real malware.

TRIGGERS:
  [1] mimikatz.exe   in %TEMP%  → BLACKLIST_MATCH    (score 95, conf HIGH)
  [2] xmrig.exe      in %TEMP%  → BLACKLIST_MATCH    (score 95, conf HIGH)
  [3] payload_x64.exe in %TEMP% → SUSPICIOUS_PATH    (score 60, conf MEDIUM)
                                   + BLACKLIST pattern "payload"
  [4] SHA-256 injected           → KNOWN_BAD_HASH    (score 100, conf HIGH)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HASHES_FILE = os.path.join(ROOT, "config", "known_bad_hashes.json")
TEMP        = os.environ.get("TEMP", os.environ.get("TMP", "C:\\Temp"))
SYSROOT     = os.environ.get("SystemRoot", "C:\\Windows")
CMD_EXE     = os.path.join(SYSROOT, "System32", "cmd.exe")

# Trigger paths
T1 = os.path.join(TEMP, "mimikatz.exe")       # blacklist name
T2 = os.path.join(TEMP, "xmrig.exe")          # blacklist name (crypto miner)
T3 = os.path.join(TEMP, "payload_x64.exe")    # blacklist pattern "payload" + suspicious path

WAIT_SECONDS = 60   # how long to keep triggers alive

# ── Colors ────────────────────────────────────────────────────────────────────
RED  = "\033[91m"
GRN  = "\033[92m"
YEL  = "\033[93m"
CYN  = "\033[96m"
WHT  = "\033[97m"
DIM  = "\033[2m"
BLD  = "\033[1m"
RST  = "\033[0m"
BAR  = "─" * 62


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def plant():
    procs   = []
    files   = []
    orig_hashes = None

    print(f"\n{BLD}{CYN}{BAR}")
    print(f"  WINDOWS MONITORING AGENT — DETECTION TRIGGER")
    print(f"{BAR}{RST}")

    if not os.path.isfile(CMD_EXE):
        print(f"{RED}ERROR: cmd.exe not found at {CMD_EXE}{RST}")
        sys.exit(1)

    # ── Trigger 1: mimikatz.exe ────────────────────────────────────────────
    print(f"\n{BLD}[1] Planting BLACKLIST trigger — mimikatz.exe{RST}")
    shutil.copy2(CMD_EXE, T1)
    files.append(T1)
    p = subprocess.Popen(
        [T1, "/K", "echo [TRIGGER] mimikatz.exe is running. Close me after the scan."],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    procs.append(p)
    print(f"    {GRN}✔ mimikatz.exe launched  (PID {p.pid})  — window opened{RST}")

    # ── Trigger 2: xmrig.exe ──────────────────────────────────────────────
    print(f"\n{BLD}[2] Planting BLACKLIST trigger — xmrig.exe{RST}")
    shutil.copy2(CMD_EXE, T2)
    files.append(T2)
    p = subprocess.Popen(
        [T2, "/K", "echo [TRIGGER] xmrig.exe is running. Close me after the scan."],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    procs.append(p)
    print(f"    {GRN}✔ xmrig.exe launched  (PID {p.pid})  — window opened{RST}")

    # ── Trigger 3: payload_x64.exe (pattern + suspicious path) ────────────
    print(f"\n{BLD}[3] Planting SUSPICIOUS_PATH + BLACKLIST_PATTERN — payload_x64.exe{RST}")
    shutil.copy2(CMD_EXE, T3)
    files.append(T3)
    p = subprocess.Popen(
        [T3, "/K", "echo [TRIGGER] payload_x64.exe is running. Close me after the scan."],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    procs.append(p)
    print(f"    {GRN}✔ payload_x64.exe launched  (PID {p.pid})  — window opened{RST}")

    # ── Trigger 4: inject hash of T3 into known_bad_hashes.json ──────────
    print(f"\n{BLD}[4] Injecting SHA-256 hash → KNOWN_BAD_HASH trigger{RST}")
    injected = sha256(T3)
    with open(HASHES_FILE, "r", encoding="utf-8") as f:
        hdata = json.load(f)
    orig_hashes = json.dumps(hdata, indent=2)
    if injected not in hdata.get("sha256", []):
        hdata.setdefault("sha256", []).append(injected)
        with open(HASHES_FILE, "w", encoding="utf-8") as f:
            json.dump(hdata, f, indent=2)
    print(f"    {GRN}✔ Hash injected: {injected[:40]}...{RST}")

    return procs, files, orig_hashes, injected


def countdown(seconds):
    print(f"\n{BLD}{YEL}{BAR}")
    print(f"  TRIGGERS ARE LIVE — RUN THE AGENT NOW IN ANOTHER TERMINAL:")
    print(f"\n    python main.py --signatures")
    print(f"    python main.py --watch 5 --dashboard")
    print(f"{BAR}{RST}\n")

    for remaining in range(seconds, 0, -1):
        bar_done  = (seconds - remaining) * 30 // seconds
        bar_left  = 30 - bar_done
        bar_str   = f"{GRN}{'█' * bar_done}{DIM}{'░' * bar_left}{RST}"
        print(
            f"\r  {bar_str}  {BLD}{remaining:>3}s{RST} until auto-cleanup   ",
            end="",
            flush=True,
        )
        time.sleep(1)
    print()


def cleanup(procs, files, orig_hashes):
    print(f"\n{BLD}{BAR}")
    print(f"  CLEANING UP")
    print(f"{BAR}{RST}\n")

    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=3)
            print(f"  {GRN}✔{RST} Killed PID {p.pid}")
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    time.sleep(1)

    for path in files:
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"  {GRN}✔{RST} Deleted {path}")
        except Exception as e:
            print(f"  {YEL}!{RST} Could not delete {path}: {e}")

    if orig_hashes:
        with open(HASHES_FILE, "w", encoding="utf-8") as f:
            f.write(orig_hashes)
        print(f"  {GRN}✔{RST} known_bad_hashes.json restored")

    print(f"\n{GRN}{BLD}  Done. All triggers removed.{RST}\n")


def print_expected():
    print(f"\n{BLD}{BAR}")
    print(f"  EXPECTED DETECTIONS")
    print(f"{BAR}{RST}")
    print(f"  {RED}[MALICIOUS][Score:95][Conf:HIGH]{RST}   BLACKLIST_MATCH      mimikatz.exe")
    print(f"  {RED}[MALICIOUS][Score:95][Conf:HIGH]{RST}   BLACKLIST_MATCH      xmrig.exe")
    print(f"  {RED}[MALICIOUS][Score:95][Conf:HIGH]{RST}   BLACKLIST_MATCH      payload_x64.exe  (pattern: payload)")
    print(f"  {RED}[MALICIOUS][Score:100][Conf:HIGH]{RST}  KNOWN_BAD_HASH       payload_x64.exe")
    print(f"  {YEL}[SUSPICIOUS][Score:60][Conf:MED]{RST}   SUSPICIOUS_EXEC_PATH payload_x64.exe  (running from Temp)")
    print()


if __name__ == "__main__":
    no_wait = "--no-wait" in sys.argv

    procs, files, orig_hashes, _ = plant()

    print_expected()

    if no_wait:
        print(f"{YEL}  --no-wait mode: triggers are live. Run the agent manually, then Ctrl+C here to clean up.{RST}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        countdown(WAIT_SECONDS)

    cleanup(procs, files, orig_hashes)
