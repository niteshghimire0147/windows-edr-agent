"""
process_detector.py — Process threat classification engine.

Detection pipeline (8 checks, highest → lowest confidence):

  Self-guard  : Skip the agent's own PID and known agent binary names
  Trust-guard : Skip known-good developer tools, common applications, and
                pattern-matched trusted names (language servers, IDE helpers)
  Check 1     : SHA-256 / MD5 hash in known-bad DB      → MALICIOUS  HASH_MATCH       ~100
  Check 2     : Explicit blacklist name match             → MALICIOUS  BLACKLIST         ~95
  Check 3     : Blacklist keyword pattern in name         → MALICIOUS  BLACKLIST         ~95
  Check 4     : Typosquat of a critical system process    → SUSPICIOUS TYPOSQUAT         ~65
  Check 5     : Whitelist + hardcoded OS-core guard       → SKIP       (no alert)
  Check 6     : Execution from Temp/AppData/Downloads     → SUSPICIOUS SUSPICIOUS_PATH   ~60
  Check 7     : Unknown process with no exe path          → SUSPICIOUS INCOMPLETE_DATA   ~40
  Check 8     : Unlisted process outside trusted dirs     → LOW        UNKNOWN           ~20

MITRE ATT&CK is assigned only when a real behavioral rule fires (Checks 1–7).
UNKNOWN (Check 8) and INCOMPLETE_DATA (Check 7) carry no MITRE when fired in
isolation — MITRE is reserved for confirmed attack techniques.

Design rationale for Check 7 severity change (MALICIOUS → SUSPICIOUS):
  A missing exe path frequently results from OS-level access restrictions on
  protected/system processes, or from psutil limitations — not from process
  hollowing.  Hollowing evidence requires additional corroborating signals
  (parent-child anomaly, suspicious path, or blacklist hit) that are caught
  by other checks.  Firing MALICIOUS on a single no-path signal produces
  unacceptable false-positive rates in production EDR deployments.
"""

import os

from utils.helpers import is_suspicious_path, is_typosquat, compute_file_hash, get_file_signature
from modules.alert_engine import (
    Alert, AlertEngine,
    SEVERITY_MALICIOUS, SEVERITY_SUSPICIOUS, SEVERITY_LOW,
    SEVERITY_HIGH,   # alias for SEVERITY_MALICIOUS — backward compat
    CATEGORY_UNAUTHORIZED, CATEGORY_TYPOSQUAT,
    CATEGORY_BLACKLIST, CATEGORY_SUSPICIOUS_PATH, CATEGORY_HASH_MATCH,
    CATEGORY_UNKNOWN, CATEGORY_INCOMPLETE_DATA,
)

# ── Virtual kernel objects ────────────────────────────────────────────────────
# These Windows kernel objects appear as processes in psutil but have no exe
# path by design.  Flagging them as injection suspects is a structural FP.
_VIRTUAL_PROCESSES = frozenset({
    "system",
    "system idle process",
    "registry",
    "memcompression",
    "memory compression",
    "secure system",
})

# ── Hard-coded OS-core process guard ─────────────────────────────────────────
# Belt-and-suspenders: these are NEVER flagged even if whitelist.json is
# incomplete. Mirrors the protected-process list in Defender / CrowdStrike.
_SYSTEM_CORE_PROCESSES = frozenset({
    "system", "system idle process", "registry", "secure system",
    "memcompression", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "lsm.exe",
    "svchost.exe", "dwm.exe", "fontdrvhost.exe", "audiodg.exe",
    "explorer.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
    "spoolsv.exe", "wudfhost.exe", "dashost.exe",
})

# ── Agent self-protection by name ─────────────────────────────────────────────
# These names are NEVER flagged regardless of which user runs the agent.
_AGENT_NAMES = frozenset({"main.exe", "main.py"})

# ── Trusted installation directories ─────────────────────────────────────────
# Processes with exe paths inside these dirs are benign commercial software.
# Generating a LOW UNKNOWN alert for them is noise, not signal.
_TRUSTED_INSTALL_DIRS = frozenset({
    "/windows/",
    "/program files/",
    "/program files (x86)/",
    "/programdata/microsoft/",
})

# ── Trusted developer tools ───────────────────────────────────────────────────
# Developer-facing binaries that are expected to run from user-writable paths
# (e.g. %LOCALAPPDATA%, workspace folders, Conda envs).  They produce no useful
# signal and would constitute pure false positives in a dev workstation context.
_TRUSTED_DEVELOPER_TOOLS = frozenset({
    # VSCode and language protocol servers (installed per-user, not Program Files)
    "language_server_windows_x64.exe",
    "language_server_windows_x86.exe",
    "language_server_linux_x64.exe",
    "language_server_osx_arm64.exe",
    # Windows Terminal console host — shipped with winget/Store, runs from user dirs
    "openconsole.exe",
    "windowsterminal.exe",
    "wt.exe",
    # Python ecosystem tools
    "pip.exe",
    "pip3.exe",
    "py.exe",
    "pytest.exe",
    "pylint.exe",
    "black.exe",
    "flake8.exe",
    "mypy.exe",
    "ruff.exe",
    "isort.exe",
    "pyflakes.exe",
    "uvicorn.exe",
    "gunicorn.exe",
    "celery.exe",
    # Node.js / npm ecosystem
    "npx.exe",
    "npx-cli.exe",
    "yarn.exe",
    "yarnpkg.exe",
    "pnpm.exe",
    "corepack.exe",
    "tsc.exe",
    "eslint.exe",
    "prettier.exe",
    "webpack.exe",
    "vite.exe",
    "esbuild.exe",
    # Git and version control
    "git-bash.exe",
    "git-lfs.exe",
    "gitgui.exe",
    "gitk.exe",
    "hub.exe",
    "gh.exe",
    "lab.exe",
    # JetBrains IDEs
    "idea64.exe",
    "idea.exe",
    "pycharm64.exe",
    "pycharm.exe",
    "webstorm64.exe",
    "webstorm.exe",
    "clion64.exe",
    "rider64.exe",
    "datagrip64.exe",
    "goland64.exe",
    "phpstorm64.exe",
    "rubymine64.exe",
    "intellij.exe",
    "jetbrains-toolbox.exe",
    # Build / compile tools
    "cmake.exe",
    "ninja.exe",
    "make.exe",
    "nmake.exe",
    "nuget.exe",
    "dotnet.exe",
    "dotnet-script.exe",
    # Container / cloud / infra tools
    "docker.exe",
    "docker-compose.exe",
    "dockerd.exe",
    "docker-desktop.exe",
    "com.docker.backend.exe",
    "kubectl.exe",
    "helm.exe",
    "terraform.exe",
    "packer.exe",
    "vagrant.exe",
    "az.exe",
    "aws.exe",
    "gcloud.exe",
    # SSH / remote access
    "ssh.exe",
    "scp.exe",
    "sftp.exe",
    "ssh-agent.exe",
    "ssh-keygen.exe",
    "putty.exe",
    "puttygen.exe",
    "pageant.exe",
    "kitty.exe",
    # Windows package managers
    "winget.exe",
    "choco.exe",
    "choco-upgrader.exe",
    "scoop.exe",
    # Unix-like tools (Git for Windows / MSYS2 / Cygwin)
    "grep.exe",
    "sed.exe",
    "awk.exe",
    "curl.exe",
    "wget.exe",
    "jq.exe",
    "unzip.exe",
    "tar.exe",
    "gzip.exe",
    "bash.exe",
    "sh.exe",
    "mintty.exe",
    # Database CLIs
    "mysql.exe",
    "mysqldump.exe",
    "psql.exe",
    "pg_dump.exe",
    "sqlcmd.exe",
    "mongosh.exe",
    "mongo.exe",
    "redis-cli.exe",
    "sqlite3.exe",
    # Testing / demo executables
    "antigravity.exe",
    "electron.exe",
    # Rust toolchain
    "cargo.exe",
    "rustc.exe",
    "rustup.exe",
    # Go toolchain
    "go.exe",
    "gofmt.exe",
})

# ── Trusted common applications ───────────────────────────────────────────────
# Well-known consumer/business applications that legitimately run from
# non-standard paths (user AppData, etc.) and are not security relevant.
_TRUSTED_APPLICATIONS = frozenset({
    # Media / entertainment
    "spotify.exe",
    "spotifw.exe",
    "vlc.exe",
    "mpv.exe",
    "wmplayer.exe",
    "groove.exe",
    "musicbee.exe",
    "foobar2000.exe",
    # Cloud storage / sync clients
    "onedrive.exe",
    "onedriveupdater.exe",
    "dropbox.exe",
    "dropboxupdate.exe",
    "googledrivefs.exe",
    "boxdrive.exe",
    # Communication / collaboration
    "teams.exe",
    "slack.exe",
    "discord.exe",
    "discordptb.exe",
    "discordcanary.exe",
    "zoom.exe",
    "skype.exe",
    "skypehost.exe",
    "telegram.exe",
    "signal.exe",
    "whatsapp.exe",
    "webex.exe",
    "gotomeeting.exe",
    # VPN clients
    "openvpn.exe",
    "openvpn-gui.exe",
    "nordvpnservice.exe",
    "nordvpn.exe",
    "expressvpn.exe",
    "protonvpn.exe",
    "mullvad-service.exe",
    # Security tools (Sysinternals, AV)
    "procexp.exe",
    "procexp64.exe",
    "autoruns.exe",
    "autorunsc.exe",
    "procmon.exe",
    "procmon64.exe",
    "handle.exe",
    "handle64.exe",
    "tcpview.exe",
    "wireshark.exe",
    "malwarebytes.exe",
    "mbamservice.exe",
    # Archive managers
    "7zfm.exe",
    "7z.exe",
    "winrar.exe",
    "peazip.exe",
    "bandizip.exe",
    "winzip.exe",
    # Text editors / IDEs
    "sublime_text.exe",
    "atom.exe",
    "notepad++.exe",
    "notepadplusplus.exe",
    "vim.exe",
    "gvim.exe",
    "emacs.exe",
    # Password managers
    "keepass.exe",
    "keepassxc.exe",
    "1password.exe",
    "bitwarden.exe",
    "dashlane.exe",
    "lastpass.exe",
    # Remote desktop / file transfer
    "mstsc.exe",
    "winscp.exe",
    "filezilla.exe",
    "anydesk.exe",
    "teamviewer.exe",
    "teamviewer_service.exe",
    "vnc.exe",
    "vncviewer.exe",
    "tigervnc.exe",
    # Browsers (belt-and-suspenders, also in whitelist)
    "chrome.exe",
    "brave.exe",
    "msedge.exe",
    "firefox.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
    # Virtualisation UI
    "virtualbox.exe",
    "virtualboxvm.exe",
    "vmware.exe",
    "vmplayer.exe",
    # Screen capture / productivity
    "sharex.exe",
    "greenshot.exe",
    "flameshot.exe",
    "snagit32.exe",
    # Gaming launchers
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    # System utilities
    "crystaldiskinfo.exe",
    "cpuz.exe",
    "gpuz.exe",
    "hwmonitor.exe",
    "hwinfo64.exe",
    "speccy.exe",
    "ccleaner.exe",
    "ccleaner64.exe",
    # AI assistant desktop apps
    "claude.exe",
    "claudedesktop.exe",
})


def _is_trusted_by_pattern(name_lower: str) -> bool:
    """
    Pattern-based trust for process names that follow a naming convention used
    by known-safe software categories.

    Covers cases where the exact binary name is not in the static frozensets
    but the name unambiguously identifies a benign category:
      - VSCode / LSP language servers  (e.g. pylance_server_win32.exe)
      - Electron renderer/GPU/utility sub-processes
      - Crash reporters embedded in Electron apps
    """
    trusted_substrings = (
        "language_server",    # VSCode LSP servers
        "language-server",    # Alternative hyphen form
        "-languageserver",    # e.g. typescript-languageserver.exe
        "lsp-",               # Generic LSP helper prefix
        "code helper",        # VSCode Helper (Renderer), Helper (GPU), etc.
        "code - insiders",    # VSCode Insiders
        "crashpad_handler",   # Electron / Chrome crash reporter
        "crash_reporter",     # Alternative crash reporter name
    )
    trusted_suffixes = (
        "_ls.exe",            # Language server suffix
        "_lsp.exe",           # LSP suffix
        "-lsp.exe",           # Hyphen variant
    )
    for sub in trusted_substrings:
        if sub in name_lower:
            return True
    for suf in trusted_suffixes:
        if name_lower.endswith(suf):
            return True
    return False


def _is_trusted_install_path(exe: str) -> bool:
    """Return True if exe resides in a standard OS / vendor installation dir."""
    if not exe:
        return False
    norm = exe.replace("\\", "/").lower()
    return any(d in norm for d in _TRUSTED_INSTALL_DIRS)


def _compute_unknown_score(exe: str, username: str) -> int:
    """
    Context-aware risk score for an unlisted process (LOW tier, 20–30).

    Nudges the score upward for signals that make an unknown process slightly
    more interesting without crossing into SUSPICIOUS territory:
      +4  running as a privileged system account
      +4  outside all trusted install directories
      +2  numeric suffix in the binary name (common in dropper naming)
    """
    score = 20
    u = (username or "").lower()
    if "system" in u or "localservice" in u or "networkservice" in u:
        score += 4
    if exe and not _is_trusted_install_path(exe):
        score += 4
    basename = os.path.basename(exe).lower() if exe else ""
    stem = basename.replace(".exe", "")
    if stem and any(c.isdigit() for c in stem):
        score += 2
    return min(30, score)


class ProcessDetector:
    """Classifies running processes using behavioral and signature-based rules."""

    def detect_unauthorized(
        self,
        processes: list[dict],
        whitelist: list[str],
        blacklist: list[str],
        blacklist_patterns: list[str],
        rules: dict,
        engine: AlertEngine,
        bad_hashes_sha256: list[str] = None,
        bad_hashes_md5: list[str] = None,
        verify_signatures: bool = False,
    ) -> None:
        """
        Run the classification pipeline against every running process.

        Severity assignments follow the 4-tier EDR model:
          MALICIOUS  (80–100) — hash match, blacklist
          SUSPICIOUS (40–70)  — typosquat, suspicious path, no-exe-path
          LOW        (10–30)  — unlisted outside trusted dirs
          SYSTEM     (0–10)   — whitelisted / core OS (skipped, no alert)

        MITRE ATT&CK IDs are only attached when a real detection fires.
        UNKNOWN and INCOMPLETE_DATA carry no MITRE in isolation.
        """
        whitelist_lower  = {n.lower() for n in whitelist}
        blacklist_lower  = {n.lower() for n in blacklist}
        patterns_lower   = [p.lower() for p in blacklist_patterns]
        typosquats_lower = [t.lower() for t in rules.get("system_process_typosquats", [])]
        suspicious_paths = rules.get("suspicious_paths", [])
        category_mitre   = rules.get("category_mitre", {})
        bad_sha256_set   = {h.lower() for h in (bad_hashes_sha256 or [])}
        bad_md5_set      = {h.lower() for h in (bad_hashes_md5 or [])}

        _self_pid = os.getpid()

        _hash_cache: dict[str, str] = {}

        # Deduplication set for UNKNOWN (Check 8):  tracks process names that
        # have already generated a LOW alert this scan so the same binary
        # running as N instances does not produce N identical low-signal entries.
        _seen_unknown_names: set[str] = set()

        def get_hash(path: str, algo: str) -> str:
            key = f"{algo}:{path}"
            if key not in _hash_cache:
                _hash_cache[key] = compute_file_hash(path, algo)
            return _hash_cache[key]

        for proc in processes:
            name       = proc.get("name", "") or ""
            exe        = proc.get("exe",  "")  or ""
            pid        = proc.get("pid")
            username   = proc.get("username", "") or ""
            name_lower = name.lower()

            # ── Guard: skip completely empty process records ──────────────────
            # psutil can return partial records during process teardown.
            if not name and pid is None:
                continue

            # ── Self-guard ───────────────────────────────────────────────────
            if pid == _self_pid or name_lower in _AGENT_NAMES:
                continue

            # ── Extended trust guard ─────────────────────────────────────────
            # Developer tools, common applications, and pattern-matched names
            # are classified TRUSTED and never generate alerts.
            if (name_lower in _TRUSTED_DEVELOPER_TOOLS
                    or name_lower in _TRUSTED_APPLICATIONS
                    or _is_trusted_by_pattern(name_lower)):
                continue

            # ── Check 1: Known-bad hash ──────────────────────────────────────
            if exe and (bad_sha256_set or bad_md5_set):
                sha256 = get_hash(exe, "sha256") if bad_sha256_set else ""
                md5    = get_hash(exe, "md5")    if bad_md5_set    else ""

                matched_hash = matched_algo = ""
                if sha256 and sha256 in bad_sha256_set:
                    matched_hash, matched_algo = sha256, "SHA-256"
                elif md5 and md5 in bad_md5_set:
                    matched_hash, matched_algo = md5, "MD5"

                if matched_hash:
                    mitre = category_mitre.get("HASH_MATCH", {})
                    engine.add(Alert(
                        severity=SEVERITY_MALICIOUS,
                        category=CATEGORY_HASH_MATCH,
                        description=(
                            f"Known-bad hash matched: {name} "
                            f"({matched_algo}: {matched_hash[:16]}...)"
                        ),
                        pid=pid, process_name=name, exe_path=exe,
                        file_hash=matched_hash,
                        mitre_id=mitre.get("id"),
                        mitre_name=mitre.get("name"),
                        mitre_tactic=mitre.get("tactic"),
                        details={
                            "hash_algorithm": matched_algo,
                            "hash_value":     matched_hash,
                            "username":       username,
                        },
                    ))
                    continue  # Confirmed — skip remaining checks

            # ── Check 2: Explicit blacklist name ─────────────────────────────
            if name_lower in blacklist_lower:
                mitre = category_mitre.get("BLACKLIST", {})
                engine.add(Alert(
                    severity=SEVERITY_MALICIOUS,
                    category=CATEGORY_BLACKLIST,
                    description=f"Blacklisted process detected: {name}",
                    pid=pid, process_name=name, exe_path=exe,
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "exact_blacklist", "username": username},
                ))
                continue

            # ── Check 3: Blacklist keyword pattern ───────────────────────────
            matched_pattern = next((p for p in patterns_lower if p in name_lower), None)
            if matched_pattern:
                mitre = category_mitre.get("BLACKLIST", {})
                engine.add(Alert(
                    severity=SEVERITY_MALICIOUS,
                    category=CATEGORY_BLACKLIST,
                    description=(
                        f"Process name matches blacklist pattern "
                        f"'{matched_pattern}': {name}"
                    ),
                    pid=pid, process_name=name, exe_path=exe,
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={
                        "match_type": "pattern_blacklist",
                        "matched_pattern": matched_pattern,
                        "username": username,
                    },
                ))
                continue

            # ── Check 4: Typosquatting ────────────────────────────────────────
            # SUSPICIOUS tier — masquerading is behavioral evidence, not a
            # confirmed compromise.  Falls through so Check 6 (suspicious path)
            # can add a second alert if the typosquat also runs from Temp.
            _is_typosquat_hit = is_typosquat(name, typosquats_lower, system_names=True)
            if _is_typosquat_hit:
                mitre = category_mitre.get("TYPOSQUAT", {})
                sig   = get_file_signature(exe) if (verify_signatures and exe) else {}
                engine.add(Alert(
                    severity=SEVERITY_SUSPICIOUS,
                    category=CATEGORY_TYPOSQUAT,
                    description=f"Possible typosquat of a critical system process: {name}",
                    pid=pid, process_name=name, exe_path=exe,
                    signed=sig.get("signed"), sign_subject=sig.get("subject"),
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={
                        "match_type":       "typosquat",
                        "username":         username,
                        "signature_status": sig.get("status", "not_checked"),
                    },
                ))
                # Fall through to Check 6 (suspicious path reinforces typosquat)

            # ── Check 5: Whitelist + core-OS guard ───────────────────────────
            if name_lower in whitelist_lower or name_lower in _SYSTEM_CORE_PROCESSES:
                continue

            # ── Check 6: Suspicious execution path ───────────────────────────
            # SUSPICIOUS tier — execution from a user-writable directory is
            # behavioral evidence of defense evasion (T1036.005).
            if exe and is_suspicious_path(exe, suspicious_paths):
                mitre = category_mitre.get("SUSPICIOUS_PATH", {})
                sig   = get_file_signature(exe) if (verify_signatures and exe) else {}
                engine.add(Alert(
                    severity=SEVERITY_SUSPICIOUS,
                    category=CATEGORY_SUSPICIOUS_PATH,
                    description=(
                        f"Process executing from suspicious directory: "
                        f"{name} -> {exe}"
                    ),
                    pid=pid, process_name=name, exe_path=exe,
                    signed=sig.get("signed"), sign_subject=sig.get("subject"),
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={
                        "match_type":       "suspicious_path",
                        "username":         username,
                        "signature_status": sig.get("status", "not_checked"),
                    },
                ))
                continue

            # ── Check 7: Unknown process with no executable path ─────────────
            # SUSPICIOUS tier (downgraded from MALICIOUS — see module docstring).
            #
            # Virtual kernel objects (System, Registry, MemCompression) are
            # excluded — they have no exe by design and are not suspicious.
            #
            # PIDs below 500 are reserved by Windows for protected/kernel
            # processes (lsaiso.exe, smss.exe early instances, etc.).  These
            # legitimately have no accessible exe path due to Isolated User
            # Mode or PPL protection — not because of injection.  Flagging
            # them generates guaranteed false positives with no analyst value.
            if not exe and name_lower not in _VIRTUAL_PROCESSES and not (pid is not None and pid < 500):
                engine.add(Alert(
                    severity=SEVERITY_SUSPICIOUS,
                    category=CATEGORY_INCOMPLETE_DATA,
                    description=(
                        f"Process has no resolvable executable path "
                        f"(access-denied or injection suspect): "
                        f"{name} (PID {pid if pid is not None else 'N/A'})"
                    ),
                    pid=pid, process_name=name, exe_path="",
                    details={
                        "match_type": "no_exe_path",
                        "username":   username,
                        "note": (
                            "Possible causes: OS access restriction on protected process, "
                            "psutil timing race, or hollowed/injected process. "
                            "Correlate with parent-child alerts before escalating."
                        ),
                    },
                ))
                continue

            # ── Check 8: Unlisted (unknown) process ──────────────────────────
            # LOW tier, no MITRE — inventory observation, not a confirmed attack.
            # Only alerts for processes OUTSIDE standard install dirs.
            #
            # Deduplication: same binary running as N instances is reported once.
            # Multiple PIDs for the same binary name add no analyst value.
            if not _is_typosquat_hit and not _is_trusted_install_path(exe):
                if name_lower in _seen_unknown_names:
                    continue   # already reported this name this scan
                _seen_unknown_names.add(name_lower)

                engine.add(Alert(
                    severity=SEVERITY_LOW,
                    category=CATEGORY_UNKNOWN,
                    description=f"Unknown (unlisted) process outside standard install dirs: {name}",
                    pid=pid, process_name=name, exe_path=exe,
                    score=_compute_unknown_score(exe, username),
                    details={"match_type": "unlisted", "username": username},
                ))
