"""
process_detector.py — Unauthorized, rogue, typosquatting, and hash-matched process detection.
"""

from utils.helpers import is_suspicious_path, is_typosquat, compute_file_hash, get_file_signature
from modules.alert_engine import (
    Alert, AlertEngine,
    SEVERITY_HIGH, SEVERITY_MEDIUM,
    CATEGORY_UNAUTHORIZED, CATEGORY_TYPOSQUAT,
    CATEGORY_BLACKLIST, CATEGORY_SUSPICIOUS_PATH, CATEGORY_HASH_MATCH,
)


class ProcessDetector:
    """Detects unauthorized, blacklisted, rogue, and typosquatting processes."""

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
        Analyze each process against whitelist/blacklist/hash rules.

        Checks (highest → lowest severity):
          1. SHA-256 / MD5 hash matches known-bad database   → HIGH  (HASH_MATCH)
          2. Explicit blacklist name match                    → HIGH  (BLACKLIST)
          3. Blacklist keyword pattern match                  → HIGH  (BLACKLIST)
          4. Typosquatting of a critical system process       → HIGH  (TYPOSQUAT)
          5. Running from a suspicious directory              → HIGH  (SUSPICIOUS_PATH)
          6. No executable path (possible process hollowing)  → MEDIUM (UNAUTHORIZED)
          7. Not on whitelist                                 → MEDIUM (UNAUTHORIZED)
        """
        whitelist_lower     = {n.lower() for n in whitelist}
        blacklist_lower     = {n.lower() for n in blacklist}
        patterns_lower      = [p.lower() for p in blacklist_patterns]
        typosquats_lower    = [t.lower() for t in rules.get("system_process_typosquats", [])]
        suspicious_paths    = rules.get("suspicious_paths", [])
        category_mitre      = rules.get("category_mitre", {})
        bad_sha256_set      = {h.lower() for h in (bad_hashes_sha256 or [])}
        bad_md5_set         = {h.lower() for h in (bad_hashes_md5 or [])}

        # Cache hashes we've already computed (path → hash) to avoid re-reading files
        _hash_cache: dict[str, str] = {}

        def get_hash(path: str, algo: str) -> str:
            cache_key = f"{algo}:{path}"
            if cache_key not in _hash_cache:
                _hash_cache[cache_key] = compute_file_hash(path, algo)
            return _hash_cache[cache_key]

        for proc in processes:
            name     = proc.get("name", "") or ""
            exe      = proc.get("exe", "")  or ""
            pid      = proc.get("pid")
            username = proc.get("username", "") or ""
            name_lower = name.lower()

            # ── Check 1: Hash match ──────────────────────────────────────
            if exe and (bad_sha256_set or bad_md5_set):
                sha256 = get_hash(exe, "sha256") if bad_sha256_set else ""
                md5    = get_hash(exe, "md5")    if bad_md5_set    else ""

                matched_hash = ""
                matched_algo = ""
                if sha256 and sha256 in bad_sha256_set:
                    matched_hash, matched_algo = sha256, "SHA-256"
                elif md5 and md5 in bad_md5_set:
                    matched_hash, matched_algo = md5, "MD5"

                if matched_hash:
                    mitre = category_mitre.get("HASH_MATCH", {})
                    engine.add(Alert(
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_HASH_MATCH,
                        description=f"Known-bad hash matched: {name} ({matched_algo}: {matched_hash[:16]}...)",
                        pid=pid,
                        process_name=name,
                        exe_path=exe,
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
                    continue  # Confirmed bad — no need for further checks

            # ── Check 2: Explicit blacklist ──────────────────────────────
            if name_lower in blacklist_lower:
                mitre = category_mitre.get("BLACKLIST", {})
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_BLACKLIST,
                    description=f"Blacklisted process detected: {name}",
                    pid=pid,
                    process_name=name,
                    exe_path=exe,
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "exact_blacklist", "username": username},
                ))
                continue

            # ── Check 3: Blacklist keyword pattern ───────────────────────
            matched_pattern = next((p for p in patterns_lower if p in name_lower), None)
            if matched_pattern:
                mitre = category_mitre.get("BLACKLIST", {})
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_BLACKLIST,
                    description=f"Process name matches blacklist pattern '{matched_pattern}': {name}",
                    pid=pid,
                    process_name=name,
                    exe_path=exe,
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "pattern_blacklist", "matched_pattern": matched_pattern, "username": username},
                ))
                continue

            # ── Check 4: Typosquatting ────────────────────────────────────
            if is_typosquat(name, typosquats_lower, system_names=True):
                mitre = category_mitre.get("TYPOSQUAT", {})
                sig = get_file_signature(exe) if (verify_signatures and exe) else {}
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_TYPOSQUAT,
                    description=f"Possible typosquat of a critical system process: {name}",
                    pid=pid,
                    process_name=name,
                    exe_path=exe,
                    signed=sig.get("signed"),
                    sign_subject=sig.get("subject"),
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "typosquat", "username": username,
                             "signature_status": sig.get("status", "not_checked")},
                ))
                # Fall through — still check for suspicious path

            # ── Check 5: Suspicious execution path ───────────────────────
            # Skip for whitelisted processes — they are known-good even from ProgramData
            if name_lower in whitelist_lower:
                continue

            if exe and is_suspicious_path(exe, suspicious_paths):
                mitre = category_mitre.get("SUSPICIOUS_PATH", {})
                sig = get_file_signature(exe) if (verify_signatures and exe) else {}
                engine.add(Alert(
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_SUSPICIOUS_PATH,
                    description=f"Process running from suspicious directory: {name} -> {exe}",
                    pid=pid,
                    process_name=name,
                    exe_path=exe,
                    signed=sig.get("signed"),
                    sign_subject=sig.get("subject"),
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "suspicious_path", "username": username,
                             "signature_status": sig.get("status", "not_checked")},
                ))
                continue

            # ── Check 6: No executable path (possible injection / hollowing) ──
            if not exe and name_lower not in ("system", "system idle process", "registry", ""):
                mitre = category_mitre.get("UNAUTHORIZED", {})
                engine.add(Alert(
                    severity=SEVERITY_MEDIUM,
                    category=CATEGORY_UNAUTHORIZED,
                    description=f"Process with no resolvable executable (possible injection): {name} (PID {pid})",
                    pid=pid,
                    process_name=name,
                    exe_path="",
                    mitre_id=mitre.get("id"),
                    mitre_name=mitre.get("name"),
                    mitre_tactic=mitre.get("tactic"),
                    details={"match_type": "no_exe_path", "username": username},
                ))
                continue

            # ── Check 7: Not on whitelist ─────────────────────────────────
            if name_lower not in whitelist_lower:
                engine.add(Alert(
                    severity=SEVERITY_MEDIUM,
                    category=CATEGORY_UNAUTHORIZED,
                    description=f"Unknown / unlisted process detected: {name}",
                    pid=pid,
                    process_name=name,
                    exe_path=exe,
                    details={"match_type": "not_whitelisted", "username": username, "exe_path": exe},
                ))
