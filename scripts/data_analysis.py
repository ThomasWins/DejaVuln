import argparse
import json
import sqlite3
from datetime import datetime, timezone
import os
import glob
import shutil

import pandas as pd
import datacompy


TRANSITIONS_REQUIRED_COLUMNS = ("vuln_id", "old_status", "new_status", "detected_at")

VULNS_ID_SOURCE_COLUMNS = ("asset_id", "plugin_id")
VULNS_STATUS_SOURCE_COLUMN = "state"

REQUIRED_VULN_COLUMNS = (
    "asset_id",
    "plugin_id",
    "state",
    "severity",
    "asset_hostname",
    "plugin_name",
    "first_found_dt",
    "last_found_dt",
    "last_fixed_dt",
)


def load_table(db_path: str, table: str, id_col: str, status_col: str) -> pd.DataFrame:
    # Load id + status columns from a sqlite table

    if not os.path.exists(db_path):
        raise Exception(f"database file not found: {db_path}")
    if os.path.getsize(db_path) == 0:
        raise Exception(f"database file is empty: {db_path}")

    con = sqlite3.connect(db_path)
    try:
        cur = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if not cur.fetchone():
            raise Exception(f"no such table: {table}")

        cols = {row[1] for row in con.execute(f"PRAGMA table_info('{table}')").fetchall()}

        if table == "transitions":
            missing = [c for c in TRANSITIONS_REQUIRED_COLUMNS if c not in cols]
            if missing:
                raise Exception(f"table '{table}' is missing required column(s): {missing}")

            rows = pd.read_sql_query(
                "SELECT vuln_id, old_status, new_status, detected_at FROM transitions", con
            )
            rows = rows.sort_values(["vuln_id", "detected_at"], kind="mergesort")
            rows = rows.drop_duplicates(subset=["vuln_id"], keep="last")
            rows["status"] = rows["new_status"].fillna(rows["old_status"])
            df = rows[["vuln_id", "status"]].copy()
            df.columns = [id_col, status_col]

        elif table == "vulns":
            required = list(VULNS_ID_SOURCE_COLUMNS) + [VULNS_STATUS_SOURCE_COLUMN]
            missing = [c for c in required if c not in cols]
            if missing:
                raise Exception(f"table '{table}' is missing required column(s): {missing}")

            query = (
                f'SELECT asset_id || "|" || plugin_id AS "{id_col}", '
                f'{VULNS_STATUS_SOURCE_COLUMN} AS "{status_col}" FROM "{table}"'
            )
            df = pd.read_sql_query(query, con)

        else:
            raise Exception(
                f"unrecognized table '{table}"
            )
    except Exception as e:
        raise SystemExit(
            f"Failed to read table '{table}' (columns '{id_col}', '{status_col}') "
            f"from {db_path}: {e}"
        )
    finally:
        con.close()

    # Normalize string dtype, trimmed, for status comparison
    df[id_col] = df[id_col].astype(str).str.strip()
    df[status_col] = df[status_col].astype(str).str.strip()
    return df


def normalize_status(value: str | None, fixed_values, reopened_values) -> str | None:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in fixed_values:
        return "fixed"
    if v in reopened_values:
        return "reopened"
    return v 


def serialize_patch_payload(patch_data: dict | None, vuln_id: str) -> str:
    # Serialize patch payload data for a vulnerability into the JSON string
    if not patch_data:
        return "[]"

    patch_payload = patch_data.get(vuln_id, [])
    if isinstance(patch_payload, (list, tuple)):
        return json.dumps(list(patch_payload))
    return json.dumps(patch_payload)


def detect_transitions(
    old_df: pd.DataFrame,
    new_df: pd.DataFrame,
    id_col: str,
    status_col: str,
    fixed_values,
    reopened_values,
    patch_data: dict | None = None,
    detected_at: str = "",
):
    # Return transition rows for vulnerabilities present in new or old db
    old_cols = [id_col, status_col]
    new_cols = [id_col, status_col]
    old_view = old_df[old_cols].copy()
    new_view = new_df[new_cols].copy()

    old_view.columns = [id_col, f"{status_col}_old"]
    new_view.columns = [id_col, f"{status_col}_new"]

    merged = old_view.merge(new_view, on=id_col, how="outer")
    merged = merged.fillna({f"{status_col}_old": None, f"{status_col}_new": None})

    rows = []
    for _, row in merged.iterrows():
        old_status = row[f"{status_col}_old"]
        new_status = row[f"{status_col}_new"]

        old_missing = pd.isna(old_status) or old_status is None
        new_missing = pd.isna(new_status) or new_status is None

        old_norm = normalize_status(old_status, fixed_values, reopened_values)
        new_norm = normalize_status(new_status, fixed_values, reopened_values)

        patch_payload = serialize_patch_payload(patch_data, row[id_col])

        if old_missing and not new_missing:
            rows.append((row[id_col], None, new_status, "new_vulnerability", patch_payload, detected_at))
        elif new_missing and not old_missing:
            rows.append((row[id_col], old_status, None, "removed_vulnerability", patch_payload, detected_at))
        elif old_norm == "fixed" and new_norm == "reopened":
            rows.append((row[id_col], old_status, new_status, "fixed_to_reopened", patch_payload, detected_at))
        elif old_norm == "reopened" and new_norm == "fixed":
            rows.append((row[id_col], old_status, new_status, "reopened_to_fixed", patch_payload, detected_at))
        elif old_norm != new_norm:
            rows.append((row[id_col], old_status, new_status, "status_change", patch_payload, detected_at))

    return rows


def ensure_history_db(history_db: str) -> sqlite3.Connection:
    con = sqlite3.connect(history_db)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT NOT NULL,
            old_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            transition_type TEXT NOT NULL,   -- 'fixed_to_reopened' or 'reopened_to_fixed'
            patch_data TEXT NOT NULL DEFAULT '[]',
            detected_at TEXT NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS summary (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            fixed_to_reopened_count INTEGER DEFAULT 0,
            reopened_to_fixed_count INTEGER DEFAULT 0,
            vuln_with_most_transitions TEXT,
            most_transitions_count INTEGER DEFAULT 0,
            top_vulns TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL
        )
        """
    )
    con.execute(
        """
        INSERT OR IGNORE INTO summary (id, updated_at)
        VALUES (1, ?)
        """,
        (datetime.now(timezone.utc).isoformat(),),
    )
    con.commit()
    return con


def ensure_vuln_stats_table(history_db: str) -> None:
    """Create a vuln_stats table in the history DB to hold per-vulnerability aggregates."""
    con = sqlite3.connect(history_db)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS vuln_stats (
                vuln_id TEXT PRIMARY KEY,
                asset_id TEXT,
                plugin_id INTEGER,
                state TEXT,
                severity TEXT,
                asset_hostname TEXT,
                plugin_name TEXT,
                first_found_dt TEXT,
                last_found_dt TEXT,
                last_fixed_dt TEXT,
                transition_count INTEGER DEFAULT 0,
                last_transition_type TEXT,
                transition_fixed_to_reopened INTEGER DEFAULT 0,
                transition_reopened_to_fixed INTEGER DEFAULT 0,
                updated_at TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()


def refresh_history_db(
    history_db: str,
    vuln_db_path: str,
    fixed_values=None,
    reopened_values=None,
    dry_run: bool = False,
    patch_data: dict | None = None,
) -> None:
    # Refresh transition_history.db from the latest TenableVulnData export

    if not os.path.exists(vuln_db_path):
        raise SystemExit(f"Vuln DB not found: {vuln_db_path}")

    fixed_values = fixed_values or {"fixed", "closed", "resolved"}
    reopened_values = reopened_values or {"reopened", "open", "re-opened", "re_opened"}

    ensure_history_db(history_db)
    ensure_vuln_stats_table(history_db)

    con_v = sqlite3.connect(vuln_db_path)
    try:
        cols = {r[1] for r in con_v.execute("PRAGMA table_info('vulns')").fetchall()}
        missing = [c for c in REQUIRED_VULN_COLUMNS if c not in cols]
        if missing:
            raise SystemExit(
                f"'vulns' table in {vuln_db_path} is missing required column(s): {missing}"
            )

        query = f"SELECT {', '.join(REQUIRED_VULN_COLUMNS)} FROM vulns"
        rows = con_v.execute(query).fetchall()
    finally:
        con_v.close()

    now = datetime.now(timezone.utc).isoformat()
    transitions_to_insert = []
    stats_rows = []

    hcon = sqlite3.connect(history_db)
    try:
        prior_rows = hcon.execute("SELECT vuln_id, state FROM vuln_stats").fetchall()
        prior_states = {vuln_id: state for vuln_id, state in prior_rows if vuln_id is not None}

        # transition counts and last transition type for all vuln_ids
        counts_rows = hcon.execute(
            "SELECT vuln_id, transition_type, COUNT(*) FROM transitions GROUP BY vuln_id, transition_type"
        ).fetchall()
        counts_by_vuln = {}
        for vid, ttype, cnt in counts_rows:
            counts_by_vuln.setdefault(vid, {})[ttype] = cnt

        last_rows = hcon.execute(
            """
            SELECT t.vuln_id, t.transition_type FROM transitions t
            JOIN (
                SELECT vuln_id, MAX(detected_at) AS md FROM transitions GROUP BY vuln_id
            ) m ON t.vuln_id = m.vuln_id AND t.detected_at = m.md
            """
        ).fetchall()
        last_by_vuln = {vid: ttype for vid, ttype in last_rows}

        for row in rows:
            asset_id, plugin_id, state, severity, asset_hostname, plugin_name, first_found_dt, last_found_dt, last_fixed_dt = row
            vuln_id = f"{asset_id}|{plugin_id}"
            prior_state = prior_states.get(vuln_id)
            normalized_prior = normalize_status(prior_state, fixed_values, reopened_values) if prior_state is not None else None
            normalized_current = normalize_status(state, fixed_values, reopened_values) if state is not None else None

            transition_type = None
            if normalized_prior == "fixed" and normalized_current == "reopened":
                transition_type = "fixed_to_reopened"
            elif normalized_prior == "reopened" and normalized_current == "fixed":
                transition_type = "reopened_to_fixed"

            if transition_type:
                patch_payload = serialize_patch_payload(patch_data, vuln_id) if transition_type == "reopened_to_fixed" else "[]"
                transitions_to_insert.append((
                    vuln_id,
                    prior_state,
                    state,
                    transition_type,
                    patch_payload,
                    now,
                ))

            counts_map = counts_by_vuln.get(vuln_id, {})
            fixed_to_reopened = counts_map.get("fixed_to_reopened", 0)
            reopened_to_fixed = counts_map.get("reopened_to_fixed", 0)
            transition_count = sum(counts_map.values())
            last_transition_type = last_by_vuln.get(vuln_id)

            stats_rows.append((
                vuln_id,
                asset_id,
                plugin_id,
                state,
                severity,
                asset_hostname,
                plugin_name,
                first_found_dt,
                last_found_dt,
                last_fixed_dt,
                transition_count,
                last_transition_type,
                fixed_to_reopened,
                reopened_to_fixed,
                now,
            ))
    finally:
        hcon.close()

    if dry_run:
        print(f"[dry-run] Would refresh {history_db} from {vuln_db_path} with {len(transitions_to_insert)} transitions")
        return

    hcon = sqlite3.connect(history_db)
    try:
        if transitions_to_insert:
            hcon.executemany(
                """
                INSERT INTO transitions (
                    vuln_id, old_status, new_status, transition_type, patch_data, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                transitions_to_insert,
            )

        refreshed_stats_rows = []
        # counts and last-transition after any inserts
        counts_rows = hcon.execute(
            "SELECT vuln_id, transition_type, COUNT(*) FROM transitions GROUP BY vuln_id, transition_type"
        ).fetchall()
        counts_by_vuln = {}
        for vid, ttype, cnt in counts_rows:
            counts_by_vuln.setdefault(vid, {})[ttype] = cnt

        last_rows = hcon.execute(
            """
            SELECT t.vuln_id, t.transition_type FROM transitions t
            JOIN (
                SELECT vuln_id, MAX(detected_at) AS md FROM transitions GROUP BY vuln_id
            ) m ON t.vuln_id = m.vuln_id AND t.detected_at = m.md
            """
        ).fetchall()
        last_by_vuln = {vid: ttype for vid, ttype in last_rows}

        for vuln_id, asset_id, plugin_id, state, severity, asset_hostname, plugin_name, first_found_dt, last_found_dt, last_fixed_dt, transition_count, last_transition_type, fixed_to_reopened, reopened_to_fixed, updated_at in stats_rows:
            counts_map = counts_by_vuln.get(vuln_id, {})
            refreshed_stats_rows.append((
                vuln_id,
                asset_id,
                plugin_id,
                state,
                severity,
                asset_hostname,
                plugin_name,
                first_found_dt,
                last_found_dt,
                last_fixed_dt,
                sum(counts_map.values()),
                last_by_vuln.get(vuln_id),
                counts_map.get("fixed_to_reopened", 0),
                counts_map.get("reopened_to_fixed", 0),
                updated_at,
            ))

        hcon.executemany(
            """
            INSERT INTO vuln_stats (
                vuln_id, asset_id, plugin_id, state, severity, asset_hostname, plugin_name,
                first_found_dt, last_found_dt, last_fixed_dt,
                transition_count, last_transition_type, transition_fixed_to_reopened, transition_reopened_to_fixed, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(vuln_id) DO UPDATE SET
                asset_id = excluded.asset_id,
                plugin_id = excluded.plugin_id,
                state = excluded.state,
                severity = excluded.severity,
                asset_hostname = excluded.asset_hostname,
                plugin_name = excluded.plugin_name,
                first_found_dt = excluded.first_found_dt,
                last_found_dt = excluded.last_found_dt,
                last_fixed_dt = excluded.last_fixed_dt,
                transition_count = excluded.transition_count,
                last_transition_type = excluded.last_transition_type,
                transition_fixed_to_reopened = excluded.transition_fixed_to_reopened,
                transition_reopened_to_fixed = excluded.transition_reopened_to_fixed,
                updated_at = excluded.updated_at
            """,
            refreshed_stats_rows,
        )

        # global counts
        fixed_count = int(hcon.execute("SELECT COUNT(*) FROM transitions WHERE transition_type = 'fixed_to_reopened'").fetchone()[0] or 0)
        reopened_count = int(hcon.execute("SELECT COUNT(*) FROM transitions WHERE transition_type = 'reopened_to_fixed'").fetchone()[0] or 0)

        # Fetch top 1000 vuln_id by number of transitions for summary
        top_rows = hcon.execute(
            """
            SELECT vuln_id, COUNT(*) as cnt
            FROM transitions
            GROUP BY vuln_id
            ORDER BY cnt DESC, vuln_id DESC
            LIMIT 1000
            """
        ).fetchall()

        if not top_rows:
            vuln_with_most = None
            most_count = 0
            top_vulns_json = "[]"
        else:
            vuln_with_most = top_rows[0][0]
            most_count = int(top_rows[0][1] or 0)
            top_list = []
            for vid, cnt in top_rows:
                top_list.append({"vuln_id": vid, "count": int(cnt)})
            top_vulns_json = json.dumps(top_list)

        hcon.execute(
            """
            UPDATE summary
            SET fixed_to_reopened_count = ?,
                reopened_to_fixed_count = ?,
                vuln_with_most_transitions = ?,
                most_transitions_count = ?,
                top_vulns = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (fixed_count, reopened_count, vuln_with_most, most_count, top_vulns_json, now),
        )
        hcon.commit()
    finally:
        hcon.close()


def find_latest_db_in_dir(directory: str) -> str | None:
    """Return the newest .db file path in `directory`, or None if none found."""
    if not os.path.isdir(directory):
        return None
    pattern = os.path.join(directory, "*.db")
    files = glob.glob(pattern)
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]


def resolve_db_path(path: str | None, base_dir: str) -> str | None:
    """Resolve a database path relative to the project root when needed."""
    if not path:
        return None
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(base_dir, path))


def resolve_comparison_targets(args, base_dir: str | None = None, vuln_dir: str | None = None):
    """Resolve the old/new DBs and table names for comparison.

    By default this compares the history database (transition_history.db or the
    path provided via --history-db) against the newest Tenable export DB in
    TenableVulnData/.
    """
    if base_dir is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    if vuln_dir is None:
        vuln_dir = os.path.join(base_dir, "TenableVulnData")

    history_db = resolve_db_path(getattr(args, "history_db", None), base_dir)
    latest_export = find_latest_db_in_dir(vuln_dir)

    if args.old is None and args.new is None:
        if history_db and os.path.exists(history_db):
            if not latest_export:
                raise SystemExit(f"No new Tenable export DB found in {vuln_dir}")
            return history_db, latest_export, "transitions", "vulns"
        if latest_export:
            return latest_export, latest_export, "vulns", "vulns"
        raise SystemExit(f"No --old provided and no .db files found in {vuln_dir}")

    old_db = resolve_db_path(args.old, base_dir) if args.old else history_db
    new_db = resolve_db_path(args.new, base_dir) if args.new else latest_export

    if not old_db:
        raise SystemExit(f"No --old provided and no history DB found at {history_db}")
    if not new_db:
        raise SystemExit(f"No --new provided and no .db files found in {vuln_dir}")

    old_table = args.old_table or args.table
    new_table = args.new_table or args.table
    if old_db == history_db and not args.old_table:
        old_table = "transitions"
    if new_db == latest_export and not args.new_table:
        new_table = "vulns"

    return old_db, new_db, old_table, new_table


def move_to_historical(file_path: str, base_dir: str) -> None:
    # Move 'file_path' into a HistoricalData folder under 'base_dir'
    if not file_path or not os.path.exists(file_path):
        return
    vuln_dir = os.path.join(base_dir, "TenableVulnData")
    # Only move files that came from TenableVulnData (qualys integrations later)
    try:
        abs_file = os.path.abspath(file_path)
        if not abs_file.startswith(os.path.abspath(vuln_dir)):
            return
    except Exception:
        return

    hist_dir = os.path.join(base_dir, "HistoricalData")
    os.makedirs(hist_dir, exist_ok=True)
    dest = os.path.join(hist_dir, os.path.basename(file_path))
    # If destination exists append timestamp
    if os.path.exists(dest):
        dest = dest + "." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    shutil.move(file_path, dest)


def resolve_table_for_db(db_path: str, preferred: str) -> str:
    # Verify 'preferred' exists in db_path

    con = sqlite3.connect(db_path)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        con.close()

    if preferred not in tables:
        raise SystemExit(
            f"table '{preferred}' not found in {db_path} (available tables: {sorted(tables)})"
        )
    return preferred


def main():
    parser = argparse.ArgumentParser(
        description="Track fixed<->reopened vulnerability status transitions between two SQLite DBs using datacompy."
    )
    parser.add_argument("--old", required=False, default=None, help="Path to the OLDER sqlite db (previous snapshot). If omitted, the history DB is used by default")
    parser.add_argument("--new", required=False, default=None, help="Path to the NEWER sqlite db (current snapshot). If omitted, the newest Tenable export in TenableVulnData/ is used")
    parser.add_argument("--table", default="vulns", help="Table name to use for --old/--new when --old-table/--new-table aren't given (default: vulns)")
    parser.add_argument("--old-table", dest="old_table", default=None, help="Table name in the OLD db (default: derived from --table)")
    parser.add_argument("--new-table", dest="new_table", default=None, help="Table name in the NEW db (default: derived from --table)")
    parser.add_argument("--id-col", dest="id_col", default="vuln_id", help="Name to use for the synthesized id column (default: vuln_id)")
    parser.add_argument("--status-col", dest="status_col", default="state", help="Name to use for the status column (default: state)")
    parser.add_argument("--history-db", dest="history_db", default=None, help="Path to the transition history db (default: data/transition_history.db)")
    parser.add_argument("--vuln-db", dest="vuln_db", default=None, help="Path to a specific Tenable export db to ingest (default: newest .db in TenableVulnData/)")
    parser.add_argument("--ingest", action="store_true", help="Ingest mode: refresh vuln_stats/transitions from the latest Tenable export instead of comparing two snapshots")
    parser.add_argument("--fixed-values", default="fixed,closed,resolved", help="Comma-separated status strings treated as 'fixed'")
    parser.add_argument("--reopened-values", default="reopened,open,re-opened,re_opened", help="Comma-separated status strings treated as 'reopened'")
    parser.add_argument("--report", action="store_true", help="Print the full datacompy comparison report")
    parser.add_argument("--dry-run", action="store_true", help="Detect transitions but don't write to the history db")
    args = parser.parse_args()

    old_table = args.old_table or args.table
    new_table = args.new_table or args.table
    id_col = args.id_col
    status_col = args.status_col

    fixed_values = {v.strip().lower() for v in args.fixed_values.split(",") if v.strip()}
    reopened_values = {v.strip().lower() for v in args.reopened_values.split(",") if v.strip()}

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    vuln_dir = os.path.join(base_dir, "TenableVulnData")
    if args.history_db is None:
        args.history_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "transition_history.db"))
    # make sure the data directory exists
    os.makedirs(os.path.dirname(args.history_db), exist_ok=True)

    if args.ingest or (args.old is None and args.new is None):
        vuln_db = args.vuln_db or find_latest_db_in_dir(vuln_dir)
        if not vuln_db:
            raise SystemExit(f"No Vuln DB provided and none found in {vuln_dir}")
        print(f"Refreshing history DB: {args.history_db} <- {vuln_db}")
        refresh_history_db(
            args.history_db,
            vuln_db,
            fixed_values=fixed_values,
            reopened_values=reopened_values,
            dry_run=args.dry_run,
        )
        return

    args.old, args.new, old_table, new_table = resolve_comparison_targets(
        args,
        base_dir=base_dir,
        vuln_dir=vuln_dir,
    )

    old_table = resolve_table_for_db(args.old, old_table)
    new_table = resolve_table_for_db(args.new, new_table)

    print(f"Loading '{old_table}' from {args.old} ...")
    df_old = load_table(args.old, old_table, id_col, status_col)
    print(f"Loading '{new_table}' from {args.new} ...")
    df_new = load_table(args.new, new_table, id_col, status_col)

    print(f"Old snapshot: {len(df_old)} vulnerabilities | New snapshot: {len(df_new)} vulnerabilities")

    compare = datacompy.PandasCompare(
        df_old,
        df_new,
        join_columns=[id_col],
        df1_name="old",
        df2_name="new",
    )

    if args.report:
        print("\n" + "=" * 80)
        print(compare.report())
        print("=" * 80 + "\n")

    now = datetime.now(timezone.utc).isoformat()
    rows_to_log = detect_transitions(
        df_old,
        df_new,
        id_col=id_col,
        status_col=status_col,
        fixed_values=fixed_values,
        reopened_values=reopened_values,
        patch_data=None,
        detected_at=now,
    )

    fixed_to_reopened = [r for r in rows_to_log if r[3] == "fixed_to_reopened"]
    reopened_to_fixed = [r for r in rows_to_log if r[3] == "reopened_to_fixed"]
    new_vulns = [r for r in rows_to_log if r[3] == "new_vulnerability"]
    removed_vulns = [r for r in rows_to_log if r[3] == "removed_vulnerability"]

    print("\n--- This run ---")
    print(f"Total transitions detected  : {len(rows_to_log)}")
    print(f"  fixed -> reopened           : {len(fixed_to_reopened)}")
    print(f"  reopened -> fixed           : {len(reopened_to_fixed)}")
    print(f"  new vulnerabilities         : {len(new_vulns)}")
    print(f"  removed vulnerabilities     : {len(removed_vulns)}")

    if fixed_to_reopened:
        print("\nVulnerabilities that went fixed -> reopened:")
        for row in fixed_to_reopened:
            print(f"  - {row[0]}  ({row[1]} -> {row[2]})")

    if reopened_to_fixed:
        print("\nVulnerabilities that went reopened -> fixed:")
        for row in reopened_to_fixed:
            print(f"  - {row[0]}  ({row[1]} -> {row[2]})")

    if new_vulns:
        print("\nNew vulnerabilities first seen in the latest snapshot:")
        for row in new_vulns:
            print(f"  - {row[0]}  ({row[2]})")

    if args.dry_run:
        print("\n[dry-run] Skipping write to history db.")
        return

    con = ensure_history_db(args.history_db)
    if rows_to_log:
        con.executemany(
            """
            INSERT INTO transitions
                (vuln_id, old_status, new_status, transition_type, patch_data, detected_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows_to_log,
        )
        con.commit()

    cur = con.execute(
        "SELECT transition_type, COUNT(*) FROM transitions GROUP BY transition_type"
    )
    totals = dict(cur.fetchall())
    con.close()

    print(f"\n--- Lifetime totals (from {args.history_db}) ---")
    print(f"  fixed -> reopened           : {totals.get('fixed_to_reopened', 0)}")
    print(f"  reopened -> fixed           : {totals.get('reopened_to_fixed', 0)}")

    # Only after successful run move data to historicaldata
    if not args.dry_run:
        try:
            move_to_historical(args.old, base_dir)
            move_to_historical(args.new, base_dir)
        except Exception as e:
            print(f"Warning: failed to move processed files to HistoricalData: {e}")


if __name__ == "__main__":
    main()