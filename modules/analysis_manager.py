# modules/analysis_manager.py — Core orchestration of the 5-tier EDR pipeline.
#
# IMPROVEMENTS:
#   - Tier 1 APIs now run CONCURRENTLY (ThreadPoolExecutor) — up to 4x faster
#   - BUG FIX: Cloud-MALICIOUS + file>50MB no longer silently returns without quarantine
#   - BUG FIX: LLM prompt typo "Riskh" corrected
#   - BUG FIX: Single-engine mode now warns when selected API key is missing
#   - FEATURE: Analyst feedback prompt after every malicious verdict
#   - FEATURE: Colorized output via colors module
#   - MEMORY: ml_result['features'] array deleted immediately after stage2 use

import os
import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import ollama

from .loading import Spinner
from .quarantine import quarantine_file
from .ml_engine import LocalScanner
from .scanner_api import VirusTotalAPI, AlienVaultAPI, MetaDefenderAPI, MalwareBazaarAPI
from .feedback import prompt_analyst_feedback
from .chain_correlator import ChainCorrelator
from .baseline_engine import BaselineEngine
from . import network_isolation
from . import utils
from . import colors


class ScannerLogic:
    """Orchestrates the Multi-Tier Pipeline: Cache → Cloud → ML → LLM → Containment."""

    def __init__(self):
        config = utils.load_config()
        self.api_keys      = config.get("api_keys", {})
        self.webhook_url   = config.get("webhook_url", "")
        self.ml_scanner    = LocalScanner()
        self.session_log: list[str] = []
        self.headless_mode = False
        # Daemon overwrites these references with its shared instances.
        # In CLI mode they still function independently.
        self.correlator    = ChainCorrelator()
        self.baseline      = BaselineEngine()
        utils.init_db()

    # ─────────────────────────────────────────────
    #  LOGGING
    # ─────────────────────────────────────────────

    def log_event(self, message: str, print_to_screen: bool = True):
        """Appends a message to the session log and optionally prints it."""
        if print_to_screen:
            print(message)
        self.session_log.append(message)

    # ─────────────────────────────────────────────
    #  TIER 1: CONCURRENT CLOUD CONSENSUS
    # ─────────────────────────────────────────────

    def _run_tier1_concurrent(self, file_hash: str) -> dict:
        """
        Queries all configured cloud engines CONCURRENTLY using a thread pool.
        Previously sequential (up to 20 s); now completes in the time of the
        slowest single API call (~5 s max).

        Returns a dict with 'verdict', 'context', and 'sources'.
        """
        # Build a dict of {engine_name: callable}
        engine_map = {}
        if self.api_keys.get("malwarebazaar"):
            engine_map["MalwareBazaar"] = lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash)
        if self.api_keys.get("virustotal"):
            engine_map["VirusTotal"] = lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash)
        if self.api_keys.get("alienvault"):
            engine_map["AlienVault"] = lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash)
        if self.api_keys.get("metadefender"):
            engine_map["MetaDefender"] = lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash)

        if not engine_map:
            self.log_event("[!] No API keys configured — Tier 1 skipped.")
            return {"verdict": None, "context": "No APIs configured", "sources": []}

        malicious_sources: list[str] = []
        unknown_sources: list[str] = []

        with ThreadPoolExecutor(max_workers=len(engine_map)) as pool:
            futures = {pool.submit(fn): name for name, fn in engine_map.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if result is None:
                        self.log_event(f"    -> {name}: UNKNOWN (No record / API error)")
                        unknown_sources.append(name)
                    elif result.get("verdict") == "MALICIOUS":
                        hits = result.get("engines_detected", 0)
                        colors.critical(f"    -> {name}: MALICIOUS (Hits: {hits})")
                        self.session_log.append(f"    -> {name}: MALICIOUS (Hits: {hits})")
                        malicious_sources.append(name)
                    else:
                        hits = result.get("engines_detected", 0)
                        colors.success(f"    -> {name}: SAFE (Hits: {hits})")
                        self.session_log.append(f"    -> {name}: SAFE (Hits: {hits})")
                except Exception as e:
                    self.log_event(f"    -> {name}: ERROR ({e})")

        if malicious_sources:
            verdict = "MALICIOUS"
            context = f"Consensus ({', '.join(malicious_sources)})"
        else:
            verdict = "SAFE"
            context = "Consensus (All Clean)" if not unknown_sources else f"Consensus (Clean — {len(unknown_sources)} unknown)"

        return {"verdict": verdict, "context": context, "sources": malicious_sources}

    def _run_tier1_single(self, file_hash: str, engine_name: str) -> dict | None:
        """Queries a single cloud engine and returns its result dict."""
        key_map = {
            "virustotal":    lambda: VirusTotalAPI(self.api_keys["virustotal"]).get_report(file_hash),
            "alienvault":    lambda: AlienVaultAPI(self.api_keys["alienvault"]).get_report(file_hash),
            "metadefender":  lambda: MetaDefenderAPI(self.api_keys["metadefender"]).get_report(file_hash),
            "malwarebazaar": lambda: MalwareBazaarAPI(self.api_keys["malwarebazaar"]).get_report(file_hash),
        }
        if engine_name not in key_map:
            return None
        # BUG FIX: warn if the selected engine has no key instead of silently falling through
        if not self.api_keys.get(engine_name):
            self.log_event(f"[-] '{engine_name}' API key is not configured. Falling back to consensus.")
            return self._run_tier1_concurrent(file_hash)
        return key_map[engine_name]()

    # ─────────────────────────────────────────────
    #  TIER 3: LLM ANALYST
    # ─────────────────────────────────────────────

    def generate_llm_report(
        self,
        family_name: str,
        detected_apis: list,
        file_path: str,
        confidence_score: float,
        sha256: str,
        file_size_mb: float,
    ) -> str:
        """Queries the local Ollama LLM and returns a formatted triage report."""
        max_apis = 50
        if detected_apis:
            api_context = "\n".join([f"- {api}" for api in detected_apis[:max_apis]])
            if len(detected_apis) > max_apis:
                api_context += f"\n- ... and {len(detected_apis) - max_apis} more."
        else:
            api_context = "None extracted. Likely API hashing, dynamic loading, or UPX packing."

        family_context = family_name + (
            " (Heuristic match — focus on behavioral APIs.)"
            if "Family ID #" in family_name
            else ""
        )

        prompt = f"""
[SYSTEM: EDR TRIAGE REPORT GENERATION]
Target File: {os.path.basename(file_path)}
Target SHA256: {sha256}
File Size: {file_size_mb:.2f} MB
Malware Classification: {family_context}
AI Confidence Score: {confidence_score:.2f}%
Extracted Windows APIs:
{api_context}

TASK: Generate a highly technical malware triage report for a Tier 2 SOC Analyst.
If specific APIs are listed, explain EXACTLY how they are chained to perform malicious actions.
Map APIs to MITRE ATT&CK tactics (e.g., Process Injection, Credential Access).
Do not use conversational filler. Do not introduce yourself.

Format output EXACTLY using these four headers:

### 🔴 Threat Classification
(1-2 sentences explaining the core threat and mechanism.)

### ⚙️ API Behavioral Analysis
(Explain the technical intent behind each API detected. If none, explain evasion tactics.)

### ⚠️ System Impact & Risk
(Concrete impact: data exfiltration, persistence, lateral movement potential.)

### 🛡️ Recommended Mitigation
(Actionable, technical isolation steps beyond standard quarantine.)

### 🎯 Generated YARA Rule
(Valid YARA rule. Condition section MUST check PE magic byte: `uint16(0) == 0x5A4D`.)
"""
        # BUG FIX: typo "Riskh" in the original prompt has been corrected above.

        try:
            response = ollama.chat(
                model="qwen2.5:3b",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a strictly analytical, automated Endpoint Detection and Response (EDR) triage engine.",
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.2},
            )
            return response["message"]["content"]
        except Exception as e:
            return f"[-] LLM Analyst Offline: {e}"

    # ─────────────────────────────────────────────
    #  TIER 4: CONTAINMENT & QUARANTINE
    # ─────────────────────────────────────────────

    def _prompt_quarantine(
        self,
        file_path: str,
        sha256: str,
        threat_source: str,
        verdict: str,
        filename: str = "",
    ):
        """
        Tier 4 containment entry point — called for EVERY malicious verdict.
        Execution order:
          1. Fire SOC webhook alert immediately (before any user prompt)
          2. In headless mode: auto-quarantine + network isolate
          3. In interactive mode: show threat banner, ask Y/N for quarantine,
             ask Y/N for network isolation separately, then run feedback loop
        """
        fname = filename or (os.path.basename(file_path) if file_path else sha256)

        # ── Step 1: SOC Webhook — fires unconditionally, logs result ──────────
        if self.webhook_url:
            import socket as _sock
            webhook_ok = utils.send_webhook_alert(
                self.webhook_url,
                title="🚨 Threat Detected on Endpoint",
                details={
                    "File":             fname,
                    "SHA-256":          sha256,
                    "Detection Source": threat_source,
                    "Verdict":          verdict,
                    "Host":             _sock.gethostname(),
                    "Timestamp":        __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
            if webhook_ok:
                colors.success("[+] SOC Webhook alert dispatched successfully.")
            else:
                colors.warning("[!] SOC Webhook alert FAILED — check URL in settings (Option 11).")
            self.session_log.append(f"[WEBHOOK] {'OK' if webhook_ok else 'FAILED'} — {verdict}")
        else:
            colors.warning("[!] No webhook configured — alert not dispatched. Set one in Option 11.")

        # ── Step 2: Headless mode — auto-execute containment ─────────────────
        if self.headless_mode:
            self.log_event("[!] HEADLESS: Auto-quarantining threat.")
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
            self.log_event("[!] HEADLESS: Severing network connection.")
            network_isolation.isolate_network()
            return

        # ── Step 3: Interactive mode — threat banner ──────────────────────────
        colors.critical(f"\n{'='*60}")
        colors.critical(f"  🔴  THREAT CONFIRMED")
        colors.critical(f"  Verdict  : {verdict}")
        colors.critical(f"  Source   : {threat_source}")
        colors.critical(f"  File     : {fname}")
        colors.critical(f"  SHA-256  : {sha256[:32]}...")
        colors.critical(f"{'='*60}")

        # ── Step 4: Quarantine prompt ─────────────────────────────────────────
        q_choice = input("\n[?] Quarantine this file? (Y/N): ").strip().upper()
        if q_choice == "Y":
            if file_path and os.path.isfile(file_path):
                quarantine_file(file_path)
                colors.success("[+] File quarantined successfully.")
            else:
                colors.warning("[!] File path unavailable for quarantine (hash-only scan).")
        else:
            colors.warning("[*] Quarantine skipped by analyst.")
            self.session_log.append("[*] Quarantine declined by analyst.")

        # ── Step 5: Network isolation prompt (separate decision) ──────────────
        n_choice = input("[?] Isolate host network? (Y/N): ").strip().upper()
        if n_choice == "Y":
            network_isolation.isolate_network()
            colors.critical("[!] Network isolated — restore via Option 9 when safe.")
        else:
            colors.warning("[*] Network isolation skipped by analyst.")


        # ── Step 6: AI Analyst Report ───────────────────────────────────────
        # Fires for ALL malicious verdicts (cloud, ML, cache hit).
        # Previously only triggered inside _handle_critical_ml_threat.
        ai_ans = input("\n[?] Generate AI analyst report via Ollama? (Y/N): ").strip().lower()
        if ai_ans == "y":
            spinner = Spinner("[*] Generating AI threat report (this may take a moment)...")
            spinner.start()
            report = self.generate_llm_report(
                family_name="Unknown — Cloud/Signature Detection",
                detected_apis=[],
                file_path=file_path or "",
                confidence_score=100.0,
                sha256=sha256,
                file_size_mb=0.0,
            )
            spinner.stop()
            self.log_event("\n--- AI Analyst Report ---")
            self.log_event(report)
        else:
            self.log_event("[*] AI analyst report skipped.")

        # ── Step 7: Analyst Feedback Loop ───────────────────────────────────
        prompt_analyst_feedback(sha256, fname, verdict)

    # ─────────────────────────────────────────────
    #  ML THREAT HANDLER
    # ─────────────────────────────────────────────

    def _handle_critical_ml_threat(
        self,
        file_path: str,
        sha256: str,
        file_size_mb: float,
        ml_result: dict,
    ):
        """Orchestrates Stage 2 classification and LLM reporting for ML-detected threats."""
        fam_name = "Unknown"
        features = ml_result.get("features")

        fam_ans = "y" if self.headless_mode else input("\n[?] Run Stage 2 family analysis? (Y/N): ").strip().lower()
        if fam_ans == "y" and features is not None:
            self.log_event("[*] Running Stage 2 classification...")
            fam_result = self.ml_scanner.scan_stage2(features)
            if fam_result:
                fam_name = fam_result.get("family_name", "Unknown")
                conf = fam_result.get("family_confidence", 0.0)
                self.log_event(f"[*] STAGE 2: {fam_name} ({conf:.2%} confidence)")
        else:
            self.log_event("[*] Skipping family analysis.")

        # MEMORY: delete feature array immediately after stage2 — prevents growth in daemon mode
        if features is not None:
            del ml_result["features"]

        ai_ans = "y" if self.headless_mode else input("\n[?] Generate local AI analyst report via Ollama? (Y/N): ").strip().lower()
        if ai_ans == "y":
            spinner = Spinner("[*] Generating AI threat report (this may take a moment)...")
            spinner.start()
            report = self.generate_llm_report(
                fam_name,
                ml_result.get("detected_apis", []),
                file_path,
                ml_result["score"] * 100,
                sha256,
                file_size_mb,
            )
            spinner.stop()
            self.log_event("\n--- AI Analyst Report ---")
            self.log_event(report)
        else:
            self.log_event("[*] Skipping AI analyst report.")

        self._prompt_quarantine(file_path, sha256, "Local ML Engine", "CRITICAL RISK")

    # ─────────────────────────────────────────────
    #  PUBLIC: SCAN FILE
    # ─────────────────────────────────────────────

    def scan_file(self, file_path: str):
        """Main routing pipeline for physical file scans (Tiers 0.5 → 1 → 2 → 3 → 4)."""

        # ── Tier 0: Exclusion list ──────────────────────────────────────────
        if utils.is_excluded(file_path):
            self.log_event(f"[*] ALLOWLISTED: {os.path.basename(file_path)} — bypassed per policy.")
            return

        sha256 = utils.get_sha256(file_path)
        if not sha256:
            colors.error("[-] Cannot read file — OS may have locked it.")
            return

        try:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            colors.error("[-] File was moved/deleted before scanning could begin.")
            return

        filename = os.path.basename(file_path)
        self.log_event("─" * 60)
        colors.info(f"[*] Target   : {filename}")
        self.session_log.append(f"[*] Target   : {filename}")
        self.log_event(f"[*] SHA-256  : {sha256}")
        self.log_event(f"[*] Size     : {file_size_mb:.2f} MB")

        # ── Tier 0.5: Local cache ───────────────────────────────────────────
        cached = utils.get_cached_result(sha256)
        if cached:
            colors.warning("[*] CACHE HIT — Bypassing API/ML engines")
            self.session_log.append("[*] CACHE HIT")
            self.log_event(f"    Verdict    : {cached['verdict']}")
            self.log_event(f"    Cached On  : {cached['timestamp']}")
            self.log_event(f"    Source     : {cached['source']}")
            # FIX: Cache hits for malicious verdicts still need webhook + quarantine.
            # Previously returned here silently — webhook never fired on repeat scans.
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                self._prompt_quarantine(
                    file_path, sha256,
                    f"Cache Hit ({cached['source']})",
                    cached['verdict'],
                    filename,
                )
            return

        # ── Tier 1: Cloud Intelligence ──────────────────────────────────────
        self.log_event("\n[*] Initializing Cloud Intelligence...")

        selected_engine = "consensus"
        if not self.headless_mode:
            print("[?] Select cloud engine:")
            print("  1. VirusTotal        2. AlienVault OTX")
            print("  3. MetaDefender      4. MalwareBazaar")
            print("  5. Smart Consensus (all active APIs) [recommended]")
            mapping = {"1": "virustotal", "2": "alienvault", "3": "metadefender", "4": "malwarebazaar", "5": "consensus"}
            selected_engine = mapping.get(input("  Choice (1-5): ").strip(), "consensus")

        cloud_verdict = None
        cloud_context = "N/A"

        if selected_engine == "consensus":
            self.log_event("[*] Running Smart Consensus (concurrent)...")
            result = self._run_tier1_concurrent(sha256)
            cloud_verdict = result["verdict"]
            cloud_context = result["context"]
        else:
            result = self._run_tier1_single(sha256, selected_engine)
            if result:
                cloud_verdict = result.get("verdict")
                cloud_context = selected_engine.capitalize()
                self.log_event(f"[*] {cloud_context}: {cloud_verdict} (Hits: {result.get('engines_detected', 0)})")

        if cloud_verdict:
            intel_context = f"{filename} | Tier 1: {cloud_context}"
            utils.save_cached_result(sha256, cloud_verdict, intel_context)

            if cloud_verdict == "MALICIOUS":
                colors.critical(f"\n[!] TIER 1 VERDICT: MALICIOUS — detected by {cloud_context}")
                self.session_log.append(f"[!] TIER 1 VERDICT: MALICIOUS — {cloud_context}")

                if file_size_mb > 50.0:
                    self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML limit — skipping Tier 2.")
                # FIX: Always quarantine on cloud MALICIOUS verdict regardless of file size.
                self._prompt_quarantine(file_path, sha256, cloud_context, "MALICIOUS", filename)
                return
            else:
                colors.success(f"\n[+] TIER 1 VERDICT: SAFE — {cloud_context}")
                self.session_log.append(f"[+] TIER 1 VERDICT: SAFE")

        # ── Tier 2: Local ML ────────────────────────────────────────────────
        if file_size_mb > 50.0:
            self.log_event(f"[!] File ({file_size_mb:.2f} MB) exceeds ML extraction limit. Tier 2 skipped.")
            return

        self.log_event("\n[*] Proceeding to Tier 2: Offline ML...")
        ml_result = self.ml_scanner.scan_stage1(file_path)

        if ml_result is None:
            self.log_event("[-] ML engine could not process file (invalid PE or extraction error).")
            return

        ml_verdict = ml_result["verdict"]
        score_pct = ml_result["score"]

        if ml_verdict == "CRITICAL RISK":
            colors.critical(f"[!] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")
        elif ml_verdict == "SUSPICIOUS":
            colors.warning(f"[!] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")
        else:
            colors.success(f"[+] TIER 2 VERDICT: {ml_verdict} (Score: {score_pct:.2%})")

        self.session_log.append(f"[*] TIER 2: {ml_verdict} ({score_pct:.2%})")
        ml_context = f"{filename} | Tier 2: Local ML ({score_pct:.2%})"
        utils.save_cached_result(sha256, ml_verdict, ml_context)

        # ── Feed findings into chain correlator ─────────────────────────────
        if ml_verdict == "CRITICAL RISK":
            pass  # ML_CRITICAL_RISK already handled by quarantine prompt above
        # Write suspicious API hits directly to event_timeline for chain correlator
        import sqlite3 as _sq, datetime as _dt
        _now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with _sq.connect(utils.DB_FILE) as _c:
                for api in ml_result.get("detected_apis", []):
                    _c.execute(
                        "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
                        ("SUSPICIOUS_API", f"{api} — {filename}", 0, _now),
                    )
        except Exception:
            pass
        # ────────────────────────────────────────────────────────────────────

        if ml_verdict == "CRITICAL RISK":
            self._handle_critical_ml_threat(file_path, sha256, file_size_mb, ml_result)
        elif ml_verdict == "SUSPICIOUS":
            colors.warning("[!] Anomalies detected but below isolation threshold. Sandbox testing advised.")
        else:
            colors.success("[+] File structure aligns with safe parameters.")

    # ─────────────────────────────────────────────
    #  PUBLIC: SCAN HASH
    # ─────────────────────────────────────────────

    def scan_hash(self, file_hash: str):
        """Hash-only pipeline: Cache → concurrent Tier 1 cloud consensus."""
        self.log_event("─" * 60)
        colors.info(f"[*] Manual Hash Scan: {file_hash}")
        self.session_log.append(f"[*] Manual Hash Scan: {file_hash}")

        cached = utils.get_cached_result(file_hash)
        if cached:
            colors.warning("[*] CACHE HIT — Local Threat DB")
            self.session_log.append("[*] CACHE HIT")
            self.log_event(f"    Verdict  : {cached['verdict']}")
            self.log_event(f"    Cached On: {cached['timestamp']}")
            self.log_event(f"    Source   : {cached['source']}")
            # FIX: fire webhook + quarantine prompt on cached malicious hash scans too
            cached_verdict = cached['verdict'].upper()
            if any(v in cached_verdict for v in ("MALICIOUS", "CRITICAL")):
                self._prompt_quarantine(
                    "",          # no file path for hash-only scans
                    file_hash,
                    f"Cache Hit ({cached['source']})",
                    cached['verdict'],
                    file_hash[:16] + "...",
                )
            return

        self.log_event("[*] Running Smart Consensus (concurrent)...")
        result = self._run_tier1_concurrent(file_hash)
        cloud_verdict = result["verdict"]
        cloud_context = result["context"]

        if cloud_verdict == "MALICIOUS":
            colors.critical(f"\n[!] FINAL VERDICT: MALICIOUS — {cloud_context}")
            self.session_log.append(f"[!] HASH VERDICT: MALICIOUS — {cloud_context}")
        else:
            colors.success(f"\n[+] FINAL VERDICT: SAFE — {cloud_context}")
            self.session_log.append(f"[+] HASH VERDICT: SAFE")

        if cloud_verdict:
            utils.save_cached_result(file_hash, cloud_verdict, f"Cloud Consensus ({cloud_context})")

    # ─────────────────────────────────────────────
    #  SESSION LOG
    # ─────────────────────────────────────────────

    def save_session_log(self):
        """Prompts the user and writes the session log to a timestamped .txt file."""
        if not self.session_log:
            return

        print("\n" + "=" * 50)
        ans = input("[?] Save session results to a forensic .txt log? (Y/N): ").strip().lower()
        if ans != "y":
            return

        analysis_dir = "Analysis Files"
        os.makedirs(analysis_dir, exist_ok=True)

        while True:
            filename = input("[>] Filename (e.g., my_report): ").strip() or "scan_results"
            if not filename.endswith(".txt"):
                filename += ".txt"

            filepath = os.path.join(analysis_dir, filename)

            if os.path.exists(filepath):
                overwrite = input(f"[!] '{filename}' already exists. Overwrite? (Y/N): ").strip().lower()
                if overwrite != "y":
                    print("[*] Enter a different filename.")
                    continue

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n CYBERSENTINEL SCAN REPORT\n")
                    f.write(f" Generated: {datetime.datetime.now()}\n" + "=" * 60 + "\n")
                    f.write("\n".join(self.session_log))
                    f.write("\n" + "=" * 60 + "\n END OF REPORT\n" + "=" * 60 + "\n")
                colors.success(f"\n[+] Report saved: {os.path.abspath(filepath)}")
                break
            except Exception as e:
                colors.error(f"[-] Save error: {e}")
                break
