#!/usr/bin/env python3

# puts all vuln findings into a database via the vulns/export API

import json
import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone

from tenable.io import TenableIO

# --- Configuration -----------------------------------------------------------

# Switch to config.py when done debug
ACCESS_KEY = os.environ.get("TIO_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TIO_SECRET_KEY", "")
DB_PATH    = f"data/TenableVulnData/tenable_export_{datetime.now().strftime('%m%d%Y')}.db"

# SINCE = last week
SINCE = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())
SEVERITY = ["critical", "high"]
STATE    = ["REOPENED", "FIXED"]          # "OPEN" "REOPENED" "FIXED"

# Pulling ALL vulnerabilities (weekly is about 5 min, 600MB-6GB)
MAX_FINDINGS = None

# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def init_db(conn: sqlite3.Connection) -> None:
    """Create the vulns table if it does not already exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vulns (
            -- natural composite key: one finding = one plugin on one asset
            asset_id            TEXT NOT NULL,
            plugin_id           INTEGER NOT NULL,

            -- important fields
            state               TEXT,
            severity            TEXT,
            asset_hostname      TEXT,
            plugin_name         TEXT,
            first_found_dt      TEXT,
            last_found_dt       TEXT,
            last_fixed_dt       TEXT,

            -- asset fields
            asset_uuid          TEXT,
            asset_ipv4          TEXT,
            asset_ipv6          TEXT,
            asset_fqdn          TEXT,
            asset_netbios_name  TEXT,
            asset_operating_system TEXT,
            asset_network_id    TEXT,
            asset_agent_uuid    TEXT,
            asset_tags          TEXT,   -- JSON array of {key,value} objects

            -- plugin / vulnerability definition
            plugin_family       TEXT,
            plugin_type         TEXT,
            plugin_publication_date TEXT,
            plugin_modification_date TEXT,
            plugin_description  TEXT,
            plugin_solution     TEXT,
            plugin_synopsis     TEXT,
            cvss_base_score     REAL,
            cvss3_base_score    REAL,
            cvss_vector         TEXT,
            cvss3_vector        TEXT,
            vpr_score           REAL,
            cve                 TEXT,   -- JSON array of CVE IDs
            cwe                 TEXT,   -- JSON array
            exploitability_ease TEXT,
            patch_publication_date TEXT,

            -- finding / instance fields
            first_found         INTEGER,
            last_found          INTEGER,
            last_fixed          INTEGER,
            port                INTEGER,
            protocol            TEXT,
            scan_uuid           TEXT,
            output              TEXT,

            updated_at          TEXT NOT NULL,

            PRIMARY KEY (asset_id, plugin_id)
        )
        """
    )
    conn.commit()
    log.info("Database initialized at '%s'.", DB_PATH)


# --- Helper Functions ---------------------------------------------------

# Timestamps come back as ISO strings from the export so convert to epoch
# integers for storage so they are easy to query
def _iso_to_epoch(s: str | None) -> int | None:
    if not s:
        return None
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except (ValueError, AttributeError):
        return None

def _json_or_none(value) -> str | None:
    """Serialise a list/dict to a compact JSON string, or return None."""
    if value is None:
        return None
    return json.dumps(value, separators=(",", ":"))

# ------------------------------------------------------------------------


def upsert_vuln(conn: sqlite3.Connection, vuln: dict) -> None:
    """Insert or replace a single vulnerability finding."""
    now      = datetime.now(tz=timezone.utc).isoformat()
    asset    = vuln.get("asset") or {}
    plugin   = vuln.get("plugin") or {}
    port_obj = vuln.get("port") or {}

    log.info("Processing finding: asset=%s plugin=%s severity=%s state=%s",
        asset.get("uuid"), plugin.get("id"), vuln.get("severity"), vuln.get("state"))

    first_found_raw = vuln.get("first_found")
    last_found_raw  = vuln.get("last_found")
    last_fixed_raw  = vuln.get("last_fixed")

    first_found  = _iso_to_epoch(first_found_raw)
    last_found   = _iso_to_epoch(last_found_raw)
    last_fixed   = _iso_to_epoch(last_fixed_raw)

    conn.execute(
        """
        INSERT INTO vulns (
            state, severity, asset_hostname, asset_id, plugin_name, plugin_id,
            first_found_dt, last_found_dt, last_fixed_dt,
            asset_uuid,  asset_ipv4, asset_ipv6,
            asset_fqdn, asset_netbios_name, asset_operating_system,
            asset_network_id, asset_agent_uuid, asset_tags,
            plugin_family, plugin_type,
            plugin_publication_date, plugin_modification_date,
            plugin_description, plugin_solution, plugin_synopsis,
            cvss_base_score, cvss3_base_score,
            cvss_vector, cvss3_vector, vpr_score,
            cve, cwe, exploitability_ease,
            patch_publication_date,
            first_found, last_found, last_fixed,
            port, protocol, scan_uuid, output,
            updated_at
        ) VALUES (
            :state, :severity, :asset_hostname, :asset_id, :plugin_name, :plugin_id,
            :first_found_dt, :last_found_dt, :last_fixed_dt,

            :asset_uuid, :asset_ipv4, :asset_ipv6,
            :asset_fqdn, :asset_netbios_name, :asset_operating_system,
            :asset_network_id, :asset_agent_uuid, :asset_tags,

            :plugin_family, :plugin_type,
            :plugin_publication_date, :plugin_modification_date,
            :plugin_description, :plugin_solution, :plugin_synopsis,
            :cvss_base_score, :cvss3_base_score,
            :cvss_vector, :cvss3_vector, :vpr_score,
            :cve, :cwe, :exploitability_ease,
            :patch_publication_date,
            
            :first_found, :last_found, :last_fixed,
            
            :port, :protocol, :scan_uuid, :output,
            :updated_at
        )
        ON CONFLICT(asset_id, plugin_id) DO UPDATE SET
            asset_uuid              = excluded.asset_uuid,
            asset_hostname          = excluded.asset_hostname,
            asset_ipv4              = excluded.asset_ipv4,
            asset_ipv6              = excluded.asset_ipv6,
            asset_fqdn              = excluded.asset_fqdn,
            asset_netbios_name      = excluded.asset_netbios_name,
            asset_operating_system  = excluded.asset_operating_system,
            asset_network_id        = excluded.asset_network_id,
            asset_agent_uuid        = excluded.asset_agent_uuid,
            asset_tags              = excluded.asset_tags,
            plugin_name             = excluded.plugin_name,
            plugin_family           = excluded.plugin_family,
            plugin_type             = excluded.plugin_type,
            plugin_publication_date = excluded.plugin_publication_date,
            plugin_modification_date= excluded.plugin_modification_date,
            plugin_description      = excluded.plugin_description,
            plugin_solution         = excluded.plugin_solution,
            plugin_synopsis         = excluded.plugin_synopsis,
            cvss_base_score         = excluded.cvss_base_score,
            cvss3_base_score        = excluded.cvss3_base_score,
            cvss_vector             = excluded.cvss_vector,
            cvss3_vector            = excluded.cvss3_vector,
            vpr_score               = excluded.vpr_score,
            cve                     = excluded.cve,
            cwe                     = excluded.cwe,
            exploitability_ease     = excluded.exploitability_ease,
            patch_publication_date  = excluded.patch_publication_date,
            severity                = excluded.severity,
            state                   = excluded.state,
            first_found             = excluded.first_found,
            last_found              = excluded.last_found,
            last_fixed              = excluded.last_fixed,
            first_found_dt          = excluded.first_found_dt,
            last_found_dt           = excluded.last_found_dt,
            last_fixed_dt           = excluded.last_fixed_dt,
            port                    = excluded.port,
            protocol                = excluded.protocol,
            scan_uuid               = excluded.scan_uuid,
            output                  = excluded.output,
            updated_at              = excluded.updated_at
        """,
        {
            "state":                  vuln.get("state"),
            "severity":               vuln.get("severity"),
            "asset_hostname":         asset.get("hostname"),
            "asset_id":               asset.get("uuid"),
            "plugin_name":             plugin.get("name"),
            "plugin_id":              plugin.get("id"),

            "first_found_dt": first_found_raw,
            "last_found_dt":  last_found_raw,
            "last_fixed_dt":  last_fixed_raw,

            "asset_uuid":             asset.get("uuid"),
            "asset_ipv4":             asset.get("ipv4"),
            "asset_ipv6":             asset.get("ipv6"),
            "asset_fqdn":             asset.get("fqdn"),
            "asset_netbios_name":     asset.get("netbios_name"),
            "asset_operating_system": _json_or_none(asset.get("operating_system")), # must be JSON array or None
            "asset_network_id":       asset.get("network_id"),
            "asset_agent_uuid":       asset.get("agent_uuid"),
            "asset_tags":             _json_or_none(asset.get("tags")),             # must be JSON array or None

            "plugin_family":           plugin.get("family"),
            "plugin_type":             plugin.get("type"),
            "plugin_publication_date": plugin.get("publication_date"),
            "plugin_modification_date":plugin.get("modification_date"),
            "plugin_description":      plugin.get("description"),
            "plugin_solution":         plugin.get("solution"),
            "plugin_synopsis":         plugin.get("synopsis"),
            "cvss_base_score":         (plugin.get("cvss_base_score")),
            "cvss3_base_score":        (plugin.get("cvss3_base_score")),
            "cvss_vector":             _json_or_none(plugin.get("cvss_vector")),     # must be JSON array or None
            "cvss3_vector":            _json_or_none(plugin.get("cvss3_vector")),
            "vpr_score":               (plugin.get("vpr") or {}).get("score"),
            "cve":                     _json_or_none(plugin.get("cve")),            # must be JSON array or None
            "cwe":                     _json_or_none(plugin.get("cwe")),
            "exploitability_ease":     plugin.get("exploitability_ease"),
            "patch_publication_date":  plugin.get("patch_publication_date"),

            "first_found":    first_found,
            "last_found":     last_found,
            "last_fixed":     last_fixed,

            "port":      port_obj.get("port"),
            "protocol":  port_obj.get("protocol"),
            "scan_uuid": vuln.get("scan", {}).get("uuid") if vuln.get("scan") else None,
            "output":    vuln.get("output"),

            "updated_at": now,
        },
    )

# --- Main -----------------------------------------------------------

def main() -> None:
    if not ACCESS_KEY or not SECRET_KEY:
        raise SystemExit(
            "ERROR: TIO_ACCESS_KEY and TIO_SECRET_KEY environment variables must be set."
        )

    tio = TenableIO(access_key=ACCESS_KEY, secret_key=SECRET_KEY)

    # Filters
    vuln_filters: dict = {}
    if SINCE is not None:
        vuln_filters["since"] = SINCE
    if SEVERITY is not None:
        vuln_filters["severity"] = SEVERITY
    if STATE is not None:
        vuln_filters["state"] = STATE

    # Create directory for database if it doesnt exist
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        init_db(conn)

        log.info("Starting vuln export from Tenable Vulnerability Management...")
        log.info("Export filters: %s", vuln_filters or "(none — full export)")

        count = 0
        for vuln in tio.exports.vulns(**vuln_filters):
            upsert_vuln(conn, vuln)
            count += 1
            
            if count % 100 == 0:
                conn.commit()
                log.info("  %d findings processed so far...", count)

            if MAX_FINDINGS is not None and count >= MAX_FINDINGS:
                log.info("Reached MAX_FINDINGS limit (%d). Stopping.", MAX_FINDINGS)
                break
        
        conn.commit()
        log.info("Done. %d findings stored in '%s'.", count, DB_PATH)
        log.info("Time Finished: %s", datetime.now(tz=timezone.utc).isoformat())


if __name__ == "__main__":
    main()