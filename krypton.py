#!/usr/bin/env python3
"""
CLI entrypoint.
Usage:
  python krypton.py --project my-project-id
  python krypton.py --org 123456789
  python krypton.py --project my-project-id --module tls
  python krypton.py --project my-project-id --output-dir /tmp/reports
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from core import config, store
from core.projects import get_projects
from core.report import render_html
from scanner import tls_policies, certificates, kms_keys, ssh_keys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(config.APP_NAME)

# Silence noisy third-party loggers — these emit per-request HTTP logs
# and raw 403 lines that are not actionable at INFO level
for _noisy in (
    "googleapiclient.discovery_cache",
    "googleapiclient.http",
    "googleapiclient.discovery",
    "google.auth.transport.requests",
    "urllib3.connectionpool",
):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

_MODULE_MAP = {
    config.MODULE_TLS:   tls_policies,
    config.MODULE_CERTS: certificates,
    config.MODULE_KMS:   kms_keys,
    config.MODULE_SSH:   ssh_keys,
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog=config.APP_NAME,
        description=config.APP_DESCRIPTION,
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--project", metavar="PROJECT_ID")
    scope.add_argument("--org",     metavar="ORG_ID")
    parser.add_argument("--module", choices=config.ALL_MODULES, default=None)
    parser.add_argument("--output-dir", metavar="DIR", default=".",
                        help="Directory for krypton.db and HTML reports (default: current dir).")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip HTML report generation.")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Single persistent DB — append a new scan record each run ──────────────
    db_path = output_dir / config.DB_FILENAME
    store.init_db(db_path)
    logger.info(f"Database : {db_path}")

    # ── Resolve projects ───────────────────────────────────────────────────────
    try:
        projects = get_projects(project_id=args.project, org_id=args.org)
    except Exception as exc:
        logger.error(f"Failed to resolve projects: {exc}")
        sys.exit(1)

    if not projects:
        logger.error("No projects found to scan.")
        sys.exit(1)

    scope_type = "project" if args.project else "org"
    scope_id   = args.project or args.org
    modules    = [args.module] if args.module else config.ALL_MODULES

    # ── Create scan record ─────────────────────────────────────────────────────
    scan_id = store.create_scan(
        db_path=db_path, scan_scope=scope_type,
        scope_id=scope_id, project_ids=projects,
    )
    logger.info(f"Scan ID  : {scan_id}")
    logger.info(f"Projects : {len(projects)}")

    # ── Run scanners ───────────────────────────────────────────────────────────
    try:
        for project in projects:
            logger.info(f"── {project} ──")
            proj_assets = proj_findings = 0

            for module_name in modules:
                scanner = _MODULE_MAP[module_name]
                try:
                    assets, findings = scanner.scan(project=project, scan_id=scan_id)
                except Exception as exc:
                    logger.error(f"  [{project}] Module '{module_name}' failed: {exc}")
                    if args.verbose:
                        import traceback; traceback.print_exc()
                    continue

                for asset in assets:
                    asset_id = store.write_asset(db_path, asset)
                    asset["asset_id"] = asset_id

                for finding in findings:
                    store.write_finding(db_path, finding)

                proj_assets   += len(assets)
                proj_findings += len(findings)

            logger.info(f"   {proj_assets} assets, {proj_findings} findings")

        store.complete_scan(db_path, scan_id)

    except KeyboardInterrupt:
        logger.warning("Scan interrupted.")
        store.fail_scan(db_path, scan_id)
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Scan failed: {exc}")
        store.fail_scan(db_path, scan_id)
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)

    # ── Summary ────────────────────────────────────────────────────────────────
    summary = store.compute_and_write_summary(db_path, scan_id)

    logger.info(
        f"\n{'='*55}\n"
        f"  Scan complete\n"
        f"  Assets inventoried : {summary['total_assets']}\n"
        f"  Findings           : {summary['total_findings']}\n"
        f"  Critical           : {summary['critical_count']}\n"
        f"  High               : {summary['high_count']}\n"
        f"  Medium             : {summary['medium_count']}\n"
        f"  Low                : {summary['low_count']}\n"
        f"  Informational      : {summary['informational_count']}\n"
        f"{'='*55}"
    )

    # ── HTML report ────────────────────────────────────────────────────────────
    if not args.no_report:
        timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_name = config.REPORT_FILENAME_TPL.format(
            app_name=config.APP_NAME, timestamp=timestamp
        )
        report_path = output_dir / report_name
        try:
            render_html(db_path, scan_id, report_path)
            logger.info(f"Report    : {report_path}")
        except Exception as exc:
            logger.error(f"Failed to render HTML report: {exc}")
            if args.verbose:
                import traceback; traceback.print_exc()


if __name__ == "__main__":
    main()
