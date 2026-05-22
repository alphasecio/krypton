"""
TLS Policies scanner.
Enumerates all target HTTPS and SSL proxies, resolves SSL policies,
and classifies TLS posture.

Classification labels and PQC status:
  DEFAULT_SSL_POLICY  — no policy attached (GCP default TLS 1.0)
  LEGACY_TLS          — TLS 1.0 or 1.1 explicitly configured
  WEAK_CIPHER         — COMPATIBLE or weak CUSTOM ciphers
  TLS_RESTRICTED      — MODERN/FIPS/RESTRICTED+1.2 (suboptimal, not broken)
  Inventory only      — RESTRICTED+TLS1.3 (PQC Capable)
"""

import logging
import uuid as _uuid_mod
from typing import Any, Dict, List, Optional, Tuple

from core import config
from core.auth import build_service

logger = logging.getLogger(__name__)


def _log_api_error(project: str, context: str, exc: Exception) -> None:
    msg = str(exc)
    expected = ("has not been used", "has not enabled", "SERVICE_DISABLED",
                 "is disabled", "accessNotConfigured", "PERMISSION_DENIED")
    if any(s in msg for s in expected):
        logger.debug(f"[{project}] {context} — API not enabled, skipping.")
    else:
        logger.warning(f"[{project}] {context}: {exc}")


# ── SSL policy classification ─────────────────────────────────────────────────

def _classify_ssl_policy(policy: Optional[Dict[str, Any]]):
    """
    Returns (finding_type, priority, pqc_status, detail, asset_role,
             protocol, classification).
    Returns None for finding_type when asset is inventory-only.
    """
    if policy is None:
        return (
            config.FINDING_DEFAULT_SSL_POLICY, config.PRIORITY_CRITICAL,
            config.PQC_NOT_READY,
            "No SSL policy attached. GCP default applies: COMPATIBLE profile, "
            "minimum TLS 1.0. Allows legacy protocols and weak cipher suites.",
            config.ASSET_ROLE_FINDING, "TLS_1_0",
            "TLS Endpoint — No Policy (GCP Default)",
        )

    profile     = policy.get("profile", "COMPATIBLE")
    min_tls     = policy.get("minTlsVersion", "TLS_1_0")
    features    = set(policy.get("enabledFeatures", []))
    policy_name = policy.get("name", "unknown")

    if min_tls in ("TLS_1_0", "TLS_1_1"):
        return (
            config.FINDING_LEGACY_TLS, config.PRIORITY_HIGH,
            config.PQC_NOT_READY,
            f"SSL policy '{policy_name}' allows {min_tls} (profile: {profile}). "
            "Legacy TLS is vulnerable to downgrade and protocol attacks today.",
            config.ASSET_ROLE_FINDING, min_tls,
            f"TLS Endpoint — {profile} ({min_tls})",
        )

    if profile == "CUSTOM":
        weak_found = features & config.WEAK_CIPHERS
        if weak_found:
            return (
                config.FINDING_WEAK_CIPHER, config.PRIORITY_MEDIUM,
                config.PQC_NOT_READY,
                f"SSL policy '{policy_name}' (CUSTOM profile) enables weak "
                f"cipher suite(s): {', '.join(sorted(weak_found))}.",
                config.ASSET_ROLE_FINDING, min_tls,
                "TLS Endpoint — Custom (Weak Ciphers)",
            )
        profile = "MODERN_EQUIVALENT"

    if profile == "COMPATIBLE":
        return (
            config.FINDING_WEAK_CIPHER, config.PRIORITY_MEDIUM,
            config.PQC_NOT_READY,
            f"SSL policy '{policy_name}' uses COMPATIBLE profile (minTLS: {min_tls}). "
            "COMPATIBLE permits weak RSA-based cipher suites even with TLS 1.2.",
            config.ASSET_ROLE_FINDING, min_tls,
            f"TLS Endpoint — COMPATIBLE ({min_tls})",
        )

    if profile in ("MODERN", "MODERN_EQUIVALENT"):
        return (
            config.FINDING_TLS_RESTRICTED, config.PRIORITY_LOW,
            config.PQC_NOT_READY,
            f"SSL policy '{policy_name}' uses MODERN profile (minTLS: {min_tls}). "
            "No weak ciphers, but TLS 1.3 is not enforced. "
            "Upgrade to RESTRICTED profile.",
            config.ASSET_ROLE_FINDING, min_tls,
            f"TLS Endpoint — MODERN ({min_tls})",
        )

    if profile == "FIPS_202205":
        return (
            config.FINDING_TLS_RESTRICTED, config.PRIORITY_LOW,
            config.PQC_NOT_READY,
            f"SSL policy '{policy_name}' uses FIPS_202205 profile (minTLS: {min_tls}). "
            "FIPS compliant. PQC key exchange is not yet customer-configurable.",
            config.ASSET_ROLE_FINDING, min_tls,
            f"TLS Endpoint — FIPS ({min_tls})",
        )

    if profile == "RESTRICTED":
        if min_tls == "TLS_1_3":
            # Best achievable — inventory only
            return (
                None, config.PRIORITY_INFORMATIONAL,
                config.PQC_CAPABLE,
                None, config.ASSET_ROLE_INVENTORY, "TLS_1_3",
                "TLS Endpoint — RESTRICTED (TLS 1.3 only)",
            )
        return (
            config.FINDING_TLS_RESTRICTED, config.PRIORITY_LOW,
            config.PQC_CAPABLE,
            f"SSL policy '{policy_name}': RESTRICTED profile, minTLS {min_tls}. "
            "Good posture. Consider TLS 1.3 minimum when client compatibility allows.",
            config.ASSET_ROLE_FINDING, min_tls,
            f"TLS Endpoint — RESTRICTED ({min_tls})",
        )

    return (
        config.FINDING_WEAK_CIPHER, config.PRIORITY_MEDIUM,
        config.PQC_NOT_READY,
        f"SSL policy '{policy_name}' has unrecognised profile '{profile}'. "
        "Manual review required.",
        config.ASSET_ROLE_FINDING, min_tls,
        f"TLS Endpoint — Unknown ({profile})",
    )


def _remediation(finding_type: Optional[str], profile: Optional[str]) -> str:
    if finding_type == config.FINDING_DEFAULT_SSL_POLICY:
        return ("Create an SSL policy with RESTRICTED profile and minimum TLS 1.2 "
                "(or TLS 1.3 if all clients support it). Attach it to this proxy.")
    if finding_type == config.FINDING_LEGACY_TLS:
        return ("Update the SSL policy minimum TLS version to 1.2. "
                "Migrate to RESTRICTED profile.")
    if finding_type == config.FINDING_WEAK_CIPHER:
        return ("Replace with RESTRICTED profile (minimum TLS 1.2). "
                "If CUSTOM is required, remove all RSA-based cipher suites.")
    if finding_type == config.FINDING_TLS_RESTRICTED:
        if profile in ("MODERN", "MODERN_EQUIVALENT"):
            return "Upgrade SSL policy from MODERN to RESTRICTED profile."
        if profile == "FIPS_202205":
            return "Ensure minimum TLS version is 1.2 or higher."
        return "Set minimum TLS version to 1.3 once client compatibility is confirmed."
    return "Review SSL policy configuration."


# ── API helpers ───────────────────────────────────────────────────────────────

def _get_ssl_policies(service, project: str) -> Dict[str, Dict]:
    policies: Dict[str, Dict] = {}
    try:
        resp = service.sslPolicies().list(project=project).execute()
        for p in resp.get("items", []):
            policies[p["selfLink"]] = p
    except Exception as exc:
        _log_api_error(project, "Could not list global SSL policies", exc)
    try:
        resp = service.sslPolicies().aggregatedList(project=project).execute()
        for zone_data in resp.get("items", {}).values():
            for p in zone_data.get("sslPolicies", []):
                policies[p["selfLink"]] = p
    except Exception as exc:
        _log_api_error(project, "Could not list regional SSL policies", exc)
    return policies


def _iter_https_proxies(service, project: str):
    try:
        resp = service.targetHttpsProxies().list(project=project).execute()
        for item in resp.get("items", []):
            item["_region"] = "global"; yield item
    except Exception as exc:
        _log_api_error(project, "Could not list global targetHttpsProxies", exc)
    try:
        resp = service.targetHttpsProxies().aggregatedList(project=project).execute()
        for region_key, region_data in resp.get("items", {}).items():
            for item in region_data.get("targetHttpsProxies", []):
                item["_region"] = region_key.split("/")[-1]; yield item
    except Exception as exc:
        _log_api_error(project, "Could not list regional targetHttpsProxies", exc)


def _iter_ssl_proxies(service, project: str):
    try:
        resp = service.targetSslProxies().list(project=project).execute()
        for item in resp.get("items", []):
            item["_region"] = "global"; yield item
    except Exception as exc:
        _log_api_error(project, "Could not list targetSslProxies", exc)


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    service = build_service("compute", "v1")
    assets: List[Dict]   = []
    findings: List[Dict] = []

    ssl_policies = _get_ssl_policies(service, project)
    logger.info(f"[{project}] Found {len(ssl_policies)} SSL policy/policies.")

    for resource_type, proxies in [
        ("TargetHttpsProxy", _iter_https_proxies(service, project)),
        ("TargetSslProxy",   _iter_ssl_proxies(service, project)),
    ]:
        for proxy in proxies:
            name        = proxy.get("name", "unknown")
            region      = proxy.get("_region", "global")
            self_link   = proxy.get("selfLink", "")
            policy_link = proxy.get("sslPolicy")
            policy      = ssl_policies.get(policy_link) if policy_link else None

            (finding_type, priority, pqc_status, detail,
             asset_role, protocol, classification) = _classify_ssl_policy(policy)

            profile     = policy.get("profile") if policy else None
            asset_id    = str(_uuid_mod.uuid4())

            assets.append({
                "asset_id":       asset_id,
                "scan_id":        scan_id,
                "project":        project,
                "region":         region,
                "resource_type":  resource_type,
                "resource_name":  self_link or f"projects/{project}/{name}",
                "resource_url":   f"https://console.cloud.google.com/net-services/loadbalancing/details/{project}/{name}?project={project}",
                "check_module":   config.MODULE_TLS,
                "asset_role":     asset_role,
                "classification": classification,
                "pqc_status":     pqc_status,
                "algorithm":      None,
                "protocol":       protocol,
                "raw_config":     proxy,
            })

            if finding_type is not None:
                findings.append({
                    "scan_id":       scan_id,
                    "asset_id":      asset_id,
                    "priority":      priority,
                    "finding_type":  finding_type,
                    "algorithm":     None,
                    "protocol":      protocol,
                    "key_size_bits": None,
                    "pqc_status":    pqc_status,
                    "detail":        detail,
                    "remediation":   _remediation(finding_type, profile),
                })

            logger.debug(f"[{project}] {resource_type} '{name}' [{region}] → "
                         f"{finding_type or 'inventory'} ({priority}) [{pqc_status}]")

    logger.info(f"[{project}] TLS: {len(assets)} proxies, {len(findings)} findings.")
    return assets, findings
