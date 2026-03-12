# modules/feedback.py — Analyst Feedback & Learning Loop
#
# Provides a post-scan verdict confirmation prompt that lets SOC analysts mark
# results as confirmed threats or false positives. Confirmed FPs are automatically
# written to exclusions.txt so the same file is never flagged again.
# All feedback is persisted in the analyst_feedback SQLite table for audit trails
# and future model fine-tuning.

import sqlite3
import datetime
import os
from . import utils

# ─────────────────────────────────────────────
#  SECTION 1: INTERACTIVE FEEDBACK PROMPT
# ─────────────────────────────────────────────

def prompt_analyst_feedback(sha256: str, filename: str, original_verdict: str) -> str | None:
    """
    Presents a post-scan review prompt to the analyst.

    Returns:
        'CONFIRMED'      — analyst agrees with the verdict
        'FALSE_POSITIVE' — analyst marks it as a false alarm
        None             — analyst skipped the review
    """
    print("\n" + "─" * 55)
    print(f"  [ANALYST REVIEW]  Verdict was: {original_verdict}")
    print("─" * 55)
    print("  Y  →  Confirm verdict (log as True Positive)")
    print("  F  →  False Positive (add to exclusion list)")
    print("  S  →  Skip review")
    print("─" * 55)
    choice = input("  [?] Your review (Y/F/S): ").strip().upper()

    if choice not in ("Y", "F"):
        print("  [*] Review skipped.")
        return None

    notes = ""
    analyst_verdict = "CONFIRMED" if choice == "Y" else "FALSE_POSITIVE"

    if analyst_verdict == "FALSE_POSITIVE":
        notes = input("  [?] Reason / notes (optional, Enter to skip): ").strip()
        _add_to_exclusions(filename)
        print(f"  [+] Marked as False Positive. '{filename}' added to exclusion list.")
    else:
        print("  [+] Verdict confirmed. Logged to analyst feedback database.")

    _save_feedback(sha256, filename, original_verdict, analyst_verdict, notes)
    return analyst_verdict


# ─────────────────────────────────────────────
#  SECTION 2: DATABASE OPERATIONS
# ─────────────────────────────────────────────

def _save_feedback(sha256: str, filename: str, original_verdict: str, analyst_verdict: str, notes: str):
    """Persists analyst feedback to the SQLite analyst_feedback table."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            conn.execute(
                """
                INSERT INTO analyst_feedback
                    (sha256, filename, original_verdict, analyst_verdict, notes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256,
                    filename,
                    original_verdict,
                    analyst_verdict,
                    notes,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
    except sqlite3.Error as e:
        print(f"[-] Feedback save error: {e}")


def get_feedback_stats() -> dict:
    """Returns aggregate feedback statistics for the dashboard."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            rows = conn.execute(
                "SELECT analyst_verdict, COUNT(*) FROM analyst_feedback GROUP BY analyst_verdict"
            ).fetchall()
            return {row[0]: row[1] for row in rows}
    except sqlite3.Error:
        return {}


def get_all_feedback(limit: int = 100) -> list:
    """Returns recent feedback records for display."""
    try:
        with sqlite3.connect(utils.DB_FILE) as conn:
            rows = conn.execute(
                """
                SELECT sha256, filename, original_verdict, analyst_verdict, notes, timestamp
                FROM analyst_feedback
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "sha256": r[0],
                    "filename": r[1],
                    "original_verdict": r[2],
                    "analyst_verdict": r[3],
                    "notes": r[4],
                    "timestamp": r[5],
                }
                for r in rows
            ]
    except sqlite3.Error:
        return []


# ─────────────────────────────────────────────
#  SECTION 3: EXCLUSION LIST MANAGEMENT
# ─────────────────────────────────────────────

def _add_to_exclusions(filename: str):
    """
    Appends a file/path to exclusions.txt when an analyst marks it as a false positive.
    Skips generic or placeholder names that would create overly broad exclusions.
    """
    if not filename or filename in ("Unknown", "Manual Hash", "Fleet Sync"):
        return

    exclusion_file = "exclusions.txt"
    # Don't add duplicates
    if os.path.exists(exclusion_file):
        try:
            with open(exclusion_file, "r") as f:
                if filename.lower() in f.read().lower():
                    return
        except Exception:
            pass

    try:
        with open(exclusion_file, "a") as f:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            f.write(f"\n{filename}  # Auto-added by analyst review on {ts}\n")
    except Exception:
        pass


# ─────────────────────────────────────────────
#  SECTION 4: CLI DISPLAY
# ─────────────────────────────────────────────

def display_feedback_history():
    """Prints a formatted feedback history table to the terminal."""
    records = get_all_feedback(limit=50)
    if not records:
        print("[*] No analyst feedback recorded yet.")
        return

    print("\n" + "=" * 110)
    print(f"  {'SHA-256 (Short)':<22}  {'File':<25}  {'System Verdict':<17}  {'Analyst':<15}  {'Notes':<20}  Timestamp")
    print("─" * 110)
    for r in records:
        sha_short = (r["sha256"][:20] + "..") if r["sha256"] else "N/A"
        fname = (r["filename"][:23] + "..") if r["filename"] and len(r["filename"]) > 25 else str(r["filename"])
        notes = (r["notes"][:18] + "..") if r["notes"] and len(r["notes"]) > 20 else str(r["notes"] or "")
        verdict_color = r["analyst_verdict"] or "N/A"
        print(
            f"  {sha_short:<22}  {fname:<25}  {r['original_verdict']:<17}  {verdict_color:<15}  {notes:<20}  {r['timestamp']}"
        )
    print("=" * 110)

    stats = get_feedback_stats()
    confirmed = stats.get("CONFIRMED", 0)
    fps = stats.get("FALSE_POSITIVE", 0)
    total = confirmed + fps
    fpr = (fps / total * 100) if total > 0 else 0
    print(f"\n  Totals — Confirmed: {confirmed}  |  False Positives: {fps}  |  Observed FP Rate: {fpr:.1f}%")
