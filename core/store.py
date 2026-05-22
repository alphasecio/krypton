"""
SQLite store — single persistent DB, appended to on every run.
All schema changes live here. serve.py (Phase 2) reads from the same DB.
"""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import config


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    scan_scope      TEXT NOT NULL,      -- 'project' | 'org'
    scope_id        TEXT NOT NULL,      -- project_id or org_id
    project_ids     TEXT NOT NULL,      -- JSON array
    app_name        TEXT NOT NULL,
    app_version     TEXT NOT NULL,
    status          TEXT NOT NULL       -- 'running' | 'complete' | 'failed'
);

CREATE TABLE IF NOT EXISTS crypto_assets (
    asset_id        TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    project         TEXT NOT NULL,
    region          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,      -- GCP resource type (e.g. TargetHttpsProxy)
    resource_name   TEXT NOT NULL,      -- full GCP resource path
    resource_url    TEXT,               -- GCP console URL
    check_module    TEXT NOT NULL,      -- tls_policies | certificates | kms_keys | ssh_keys
    asset_role      TEXT NOT NULL DEFAULT 'finding',  -- 'finding' | 'inventory'
    classification  TEXT,              -- human-readable cryptographic role
    pqc_status      TEXT,              -- NOT_READY | CLASSICAL | PQC_CAPABLE | PQC_READY | SAFE
    algorithm       TEXT,
    protocol        TEXT,
    raw_config      TEXT,              -- JSON snapshot at scan time
    discovered_at   TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    priority        TEXT NOT NULL,      -- CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    finding_type    TEXT NOT NULL,      -- e.g. DEFAULT_SSL_POLICY, LEGACY_TLS
    algorithm       TEXT,
    protocol        TEXT,
    key_size_bits   INTEGER,
    pqc_status      TEXT NOT NULL,
    detail          TEXT NOT NULL,
    remediation     TEXT,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (asset_id) REFERENCES crypto_assets(asset_id)
);

CREATE TABLE IF NOT EXISTS scan_summaries (
    scan_id                 TEXT PRIMARY KEY,
    total_assets            INTEGER NOT NULL DEFAULT 0,
    total_findings          INTEGER NOT NULL DEFAULT 0,
    critical_count          INTEGER NOT NULL DEFAULT 0,
    high_count              INTEGER NOT NULL DEFAULT 0,
    medium_count            INTEGER NOT NULL DEFAULT 0,
    low_count               INTEGER NOT NULL DEFAULT 0,
    informational_count     INTEGER NOT NULL DEFAULT 0,
    pqc_ready_count         INTEGER NOT NULL DEFAULT 0,
    pqc_capable_count       INTEGER NOT NULL DEFAULT 0,
    classical_count         INTEGER NOT NULL DEFAULT 0,
    not_ready_count         INTEGER NOT NULL DEFAULT 0,
    safe_count              INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset    ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority);
CREATE INDEX IF NOT EXISTS idx_assets_scan       ON crypto_assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_project    ON crypto_assets(project);
CREATE INDEX IF NOT EXISTS idx_assets_module     ON crypto_assets(check_module);
CREATE INDEX IF NOT EXISTS idx_assets_role       ON crypto_assets(asset_role);
"""


# ── Connection ────────────────────────────────────────────────────────────────

@contextmanager
def _connect(db_path: Path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    """Create tables and indexes if they don't exist. Safe to call on existing DB."""
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uuid() -> str:
    return str(uuid.uuid4())


# ── Scan lifecycle ────────────────────────────────────────────────────────────

def create_scan(db_path: Path, scan_scope: str, scope_id: str,
                project_ids: List[str]) -> str:
    scan_id = _uuid()
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO scans
               (scan_id, started_at, scan_scope, scope_id, project_ids,
                app_name, app_version, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, _now(), scan_scope, scope_id, json.dumps(project_ids),
             config.APP_NAME, config.APP_VERSION, config.SCAN_RUNNING),
        )
    return scan_id


def complete_scan(db_path: Path, scan_id: str) -> None:
    with _connect(db_path) as conn:
        conn.execute("UPDATE scans SET status=?, completed_at=? WHERE scan_id=?",
                     (config.SCAN_COMPLETE, _now(), scan_id))


def fail_scan(db_path: Path, scan_id: str) -> None:
    with _connect(db_path) as conn:
        conn.execute("UPDATE scans SET status=?, completed_at=? WHERE scan_id=?",
                     (config.SCAN_FAILED, _now(), scan_id))


# ── Asset writes ──────────────────────────────────────────────────────────────

def write_asset(db_path: Path, asset: Dict[str, Any]) -> str:
    asset_id = asset.get("asset_id") or _uuid()
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO crypto_assets
               (asset_id, scan_id, project, region, resource_type,
                resource_name, resource_url, check_module, asset_role,
                classification, pqc_status, algorithm, protocol,
                raw_config, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset_id, asset["scan_id"], asset["project"],
             asset.get("region", "global"), asset["resource_type"],
             asset["resource_name"], asset.get("resource_url"),
             asset["check_module"],
             asset.get("asset_role", config.ASSET_ROLE_FINDING),
             asset.get("classification"),
             asset.get("pqc_status"), asset.get("algorithm"),
             asset.get("protocol"),
             json.dumps(asset.get("raw_config")) if asset.get("raw_config") else None,
             _now()),
        )
    return asset_id


# ── Finding writes ────────────────────────────────────────────────────────────

def write_finding(db_path: Path, finding: Dict[str, Any]) -> str:
    finding_id = finding.get("finding_id") or _uuid()
    now = _now()
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO findings
               (finding_id, scan_id, asset_id, priority, finding_type,
                algorithm, protocol, key_size_bits, pqc_status,
                detail, remediation, first_seen_at, last_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, finding["scan_id"], finding["asset_id"],
             finding["priority"], finding["finding_type"],
             finding.get("algorithm"), finding.get("protocol"),
             finding.get("key_size_bits"), finding["pqc_status"],
             finding["detail"], finding.get("remediation"),
             now, now),
        )
    return finding_id


# ── Summary ───────────────────────────────────────────────────────────────────

def compute_and_write_summary(db_path: Path, scan_id: str) -> Dict[str, int]:
    with _connect(db_path) as conn:
        total_assets = conn.execute(
            "SELECT COUNT(*) FROM crypto_assets WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]

        priority_rows = conn.execute(
            """SELECT priority, COUNT(*) as cnt FROM findings
               WHERE scan_id=? GROUP BY priority""",
            (scan_id,),
        ).fetchall()
        priority_counts = {r["priority"]: r["cnt"] for r in priority_rows}

        # PQC status counts from assets (richer than findings-only view)
        pqc_rows = conn.execute(
            """SELECT pqc_status, COUNT(*) as cnt FROM crypto_assets
               WHERE scan_id=? GROUP BY pqc_status""",
            (scan_id,),
        ).fetchall()
        pqc_counts = {r["pqc_status"]: r["cnt"] for r in pqc_rows}

        summary = {
            "scan_id":              scan_id,
            "total_assets":         total_assets,
            "total_findings":       sum(priority_counts.values()),
            "critical_count":       priority_counts.get(config.PRIORITY_CRITICAL, 0),
            "high_count":           priority_counts.get(config.PRIORITY_HIGH, 0),
            "medium_count":         priority_counts.get(config.PRIORITY_MEDIUM, 0),
            "low_count":            priority_counts.get(config.PRIORITY_LOW, 0),
            "informational_count":  priority_counts.get(config.PRIORITY_INFORMATIONAL, 0),
            "pqc_ready_count":      pqc_counts.get(config.PQC_READY, 0),
            "pqc_capable_count":    pqc_counts.get(config.PQC_CAPABLE, 0),
            "classical_count":      pqc_counts.get(config.PQC_CLASSICAL, 0),
            "not_ready_count":      pqc_counts.get(config.PQC_NOT_READY, 0),
            "safe_count":           pqc_counts.get(config.PQC_SAFE, 0),
        }

        conn.execute(
            """INSERT OR REPLACE INTO scan_summaries
               (scan_id, total_assets, total_findings,
                critical_count, high_count, medium_count,
                low_count, informational_count, pqc_ready_count,
                pqc_capable_count, classical_count, not_ready_count, safe_count)
               VALUES
               (:scan_id, :total_assets, :total_findings,
                :critical_count, :high_count, :medium_count,
                :low_count, :informational_count, :pqc_ready_count,
                :pqc_capable_count, :classical_count, :not_ready_count, :safe_count)""",
            summary,
        )
    return summary


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_scan(db_path: Path, scan_id: str) -> Optional[Dict]:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None


def get_summary(db_path: Path, scan_id: str) -> Optional[Dict]:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_summaries WHERE scan_id=?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None


def get_assets(db_path: Path, scan_id: str,
               role: Optional[str] = None,
               module: Optional[str] = None) -> List[Dict]:
    filters = ["scan_id=?"]
    params: List[Any] = [scan_id]
    if role:
        filters.append("asset_role=?"); params.append(role)
    if module:
        filters.append("check_module=?"); params.append(module)
    where = " AND ".join(filters)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM crypto_assets WHERE {where} "
            f"ORDER BY project, check_module, resource_type, resource_name",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def get_findings(db_path: Path, scan_id: str,
                 min_priority: Optional[str] = None,
                 module: Optional[str] = None,
                 include_informational: bool = True) -> List[Dict]:
    allowed: List[str] = []
    if min_priority and min_priority in config.PRIORITY_ORDER:
        cutoff = config.PRIORITY_ORDER.index(min_priority)
        allowed = config.PRIORITY_ORDER[:cutoff + 1]
    elif not include_informational:
        allowed = [p for p in config.PRIORITY_ORDER
                   if p != config.PRIORITY_INFORMATIONAL]

    priority_filter = ""
    if allowed:
        placeholders = ",".join("?" * len(allowed))
        priority_filter = f"AND f.priority IN ({placeholders})"

    module_filter = "AND a.check_module=?" if module else ""

    sql = f"""
        SELECT f.*, a.project, a.region, a.resource_type,
               a.resource_name, a.resource_url, a.check_module
        FROM findings f
        JOIN crypto_assets a ON f.asset_id = a.asset_id
        WHERE f.scan_id=? {priority_filter} {module_filter}
        ORDER BY
            CASE f.priority
                WHEN 'CRITICAL'      THEN 1
                WHEN 'HIGH'          THEN 2
                WHEN 'MEDIUM'        THEN 3
                WHEN 'LOW'           THEN 4
                WHEN 'INFORMATIONAL' THEN 5
            END,
            a.project, a.resource_name
    """
    params_list: List[Any] = [scan_id] + allowed
    if module:
        params_list.append(module)

    with _connect(db_path) as conn:
        rows = conn.execute(sql, params_list).fetchall()
        return [dict(r) for r in rows]


def get_latest_scan_id(db_path: Path) -> Optional[str]:
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT scan_id FROM scans
               ORDER BY CASE status WHEN 'complete' THEN 0 ELSE 1 END,
                        started_at DESC LIMIT 1"""
        ).fetchone()
        return row["scan_id"] if row else None
