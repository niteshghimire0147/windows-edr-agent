"""
helpers.py — Common utility functions for the monitoring agent.
"""

import os
import hashlib
import subprocess
import datetime


def normalize_path(path: str) -> str:
    """Expand environment variables, lowercase, and normalize slashes."""
    if not path:
        return ""
    expanded = os.path.expandvars(path)
    return expanded.replace("\\", "/").lower().strip()


def is_suspicious_path(path: str, suspicious_patterns: list) -> bool:
    """Return True if the normalized path contains any suspicious directory pattern."""
    if not path:
        return False
    normalized = normalize_path(path)
    for pattern in suspicious_patterns:
        pattern_norm = normalize_path(pattern)
        if pattern_norm and pattern_norm in normalized:
            return True
    return False


def compute_file_hash(path: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash of a file. Returns the hex digest string, or "" on failure.
    Supported algorithms: 'sha256', 'md5'.
    Reads in 64 KB chunks to handle large files without loading them into memory.
    """
    if not path or not os.path.isfile(path):
        return ""
    try:
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return ""


def get_file_signature(path: str) -> dict:
    """
    Check whether a file has a valid Authenticode digital signature via PowerShell.
    Returns a dict: { signed (bool), status (str), subject (str) }.
    Fails gracefully if PowerShell or the file is inaccessible.
    """
    result = {"signed": False, "status": "Unknown", "subject": ""}
    if not path or not os.path.isfile(path):
        result["status"] = "FileNotFound"
        return result

    try:
        escaped = path.replace("'", "''")
        ps_command = (
            f"$sig = Get-AuthenticodeSignature '{escaped}'; "
            f"Write-Output \"$($sig.Status)|$($sig.SignerCertificate.Subject)\""
        )
        proc = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = proc.stdout.strip()
        if "|" in output:
            status_str, subject = output.split("|", 1)
            result["status"]  = status_str.strip()
            result["subject"] = subject.strip()
            result["signed"]  = status_str.strip().lower() == "valid"
        else:
            result["status"] = output or "ParseError"
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        result["status"] = "CheckFailed"

    return result


def timestamp_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_for_filename() -> str:
    """Return the current local time formatted for use in filenames."""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions    = previous_row[j + 1] + 1
            deletions     = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_typosquat(name: str, known_typosquats: list, system_names: bool = False,
                 distance_threshold: int = 1) -> bool:
    """
    Return True if the process name looks like a typosquat of a critical system process.
    Checks explicit list first, then optional edit-distance check.
    """
    name_lower = name.lower()

    if name_lower in [t.lower() for t in known_typosquats]:
        return True

    if system_names:
        critical = [
            "lsass.exe", "csrss.exe", "svchost.exe", "winlogon.exe",
            "wininit.exe", "services.exe", "explorer.exe", "spoolsv.exe",
            "smss.exe", "lsm.exe",
        ]
        for legit in critical:
            if name_lower == legit:
                return False
            if 0 < levenshtein_distance(name_lower, legit) <= distance_threshold:
                return True

    return False
