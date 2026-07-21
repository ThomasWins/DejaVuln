from __future__ import annotations
import argparse
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
import shutil


def parse_args():
    p = argparse.ArgumentParser(description="Clean historical data older than N days")
    p.add_argument("--days", type=int, required=True, help="Keep last N days; delete older items")
    p.add_argument("--history-db", default=None, help="Path to transition_history.db (defaults to data/transition_history.db)")
    p.add_argument("--historical-dir", default=None, help="Path to HistoricalData directory (defaults to data/HistoricalData)")
    p.add_argument("--dry-run", action="store_true", help="Show what would be deleted without removing")
    return p.parse_args()


def cleanup_files(hist_dir: Path, cutoff_dt: datetime, dry_run: bool = False):
    if not hist_dir.exists():
        print(f"Historical directory does not exist: {hist_dir}")
        return
    removed = []
    for entry in hist_dir.iterdir():
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff_dt:
                removed.append(entry)
        except Exception as e:
            print(f"Skipping {entry}: {e}")
    if not removed:
        print("No files to remove in historical directory.")
        return
    for p in removed:
        print(("DRY-RUN: would remove " if dry_run else "Removing ") + str(p))
        if not dry_run:
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
            except Exception as e:
                print(f"Failed to remove {p}: {e}")


def cleanup_db(history_db_path: Path, cutoff_iso: str, dry_run: bool = False):
    if not history_db_path.exists():
        print(f"History DB not found: {history_db_path}")
        return
    con = sqlite3.connect(str(history_db_path))
    try:
        cur = con.cursor()
        # check transitions table
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transitions'")
        if not cur.fetchone():
            print("No transitions table found in history DB.")
            return
        # Count rows to delete
        cur.execute("SELECT COUNT(*) FROM transitions WHERE detected_at < ?", (cutoff_iso,))
        cnt = cur.fetchone()[0]
        print(f"Rows matching cutoff ({cutoff_iso}): {cnt}")
        if cnt == 0:
            return
        if dry_run:
            print("DRY-RUN: would delete rows from transitions where detected_at < cutoff")
            return
        cur.execute("DELETE FROM transitions WHERE detected_at < ?", (cutoff_iso,))
        con.commit()
        print(f"Deleted {cur.rowcount} rows from transitions")
        try:
            con.execute("VACUUM")
        except Exception:
            pass
    finally:
        con.close()