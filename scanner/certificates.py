"""
Certificates scanner.

Surfaces:
  A) Classic SSL certificates (compute.sslCertificates)
  B) Certificate Manager

Asset roles:
  Google-managed certs  → inventory only  (algorithm/renewal managed by Google)
  Self-managed certs    → finding         (classical RSA/ECDSA, harvest risk)
  Expiry findings       → always emitted  (CRITICAL/HIGH regardless of cert type)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid as _uuid_mod

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


# ── PEM parsing ───────────────────────────────────────────────────────────────

def _parse_cert_pem(pem: Optional[str]) -> Tuple[Optional[str], Optional[int], Optional[datetime]]:
    if not pem:
        return None, None, None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
        cert   = x509.load_pem_x509_certificate(pem.encode())
        expiry = (cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc")
                  else cert.not_valid_after.replace(tzinfo=timezone.utc))
        pub    = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA", pub.key_size, expiry
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return f"ECDSA ({pub.curve.name})", pub.key_size, expiry
        if isinstance(pub, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, expiry
        if isinstance(pub, ed448.Ed448PublicKey):
            return "Ed448", 448, expiry
        return "UNKNOWN", None, expiry
    except ImportError:
        logger.warning("cryptography package not installed — cert PEM parsing disabled.")
        return None, None, None
    except Exception as exc:
        logger.debug(f"Failed to parse cert PEM: {exc}")
        return None, None, None


def _expiry_finding(expiry: Optional[datetime], cert_name: str,
                    asset_id: str, scan_id: str) -> Optional[Dict]:
    if expiry is None:
        return None
    days = (expiry - datetime.now(timezone.utc)).days
    if days < 0:
        return {
            "scan_id": scan_id, "asset_id": asset_id,
            "priority": config.PRIORITY_CRITICAL,
            "finding_type": config.FINDING_CERT_EXPIRED,
            "algorithm": None, "protocol": None, "key_size_bits": None,
            "pqc_status": config.PQC_NOT_READY,
            "detail": f"Certificate '{cert_name}' expired {abs(days)} day(s) ago ({expiry.date()}).",
            "remediation": "Replace this certificate immediately.",
        }
    if days <= config.CERT_EXPIRY_WARNING_DAYS:
        return {
            "scan_id": scan_id, "asset_id": asset_id,
            "priority": config.PRIORITY_HIGH,
            "finding_type": config.FINDING_CERT_EXPIRING,
            "algorithm": None, "protocol": None, "key_size_bits": None,
            "pqc_status": config.PQC_NOT_READY,
            "detail": f"Certificate '{cert_name}' expires in {days} day(s) ({expiry.date()}).",
            "remediation": "Renew this certificate before it expires.",
        }
    return None


def _algorithm_finding_type(algorithm: Optional[str]) -> str:
    if algorithm and algorithm.startswith("RSA"):   return config.FINDING_CERT_RSA
    if algorithm and algorithm.startswith("ECDSA"): return config.FINDING_CERT_ECDSA
    return config.FINDING_CERT_ECDSA


def _cert_remediation(algorithm: Optional[str]) -> str:
    return (
        f"Certificate uses {algorithm or 'a classical'} key, which is vulnerable to "
        "quantum attacks (Harvest Now Decrypt Later risk for long-lived data). "
        "No PQC certificates are yet available from public CAs. "
        "Inventory for migration when PQC PKI becomes available."
    )


# ── Classic SSL certificates ──────────────────────────────────────────────────

def _scan_classic_certs(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    try:
        service = build_service("compute", "v1")
        resp    = service.sslCertificates().aggregatedList(project=project).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list classic SSL certs", exc)
        return assets, findings

    for zone_key, zone_data in resp.get("items", {}).items():
        for cert in zone_data.get("sslCertificates", []):
            name      = cert.get("name", "unknown")
            self_link = cert.get("selfLink", f"projects/{project}/sslCertificates/{name}")
            cert_type = cert.get("type", "SELF_MANAGED")
            region    = zone_key.split("/")[-1] if "/" in zone_key else "global"
            asset_id  = str(_uuid_mod.uuid4())

            if cert_type == "MANAGED":
                assets.append({
                    "asset_id": asset_id, "scan_id": scan_id,
                    "project": project, "region": region,
                    "resource_type": "SslCertificate", "resource_name": self_link,
                    "resource_url": f"https://console.cloud.google.com/loadbalancing/advanced/sslCertificates/details/{name}?project={project}",
                    "check_module": config.MODULE_CERTS,
                    "asset_role": config.ASSET_ROLE_INVENTORY,
                    "classification": "Google-managed Certificate",
                    "pqc_status": config.PQC_CLASSICAL,
                    "algorithm": "ECDSA P-256 (Google-managed)", "protocol": None,
                    "raw_config": {k: v for k, v in cert.items() if k != "certificate"},
                })
            else:
                pem = cert.get("certificate")
                algorithm, key_size, expiry = _parse_cert_pem(pem)
                algo_str = f"{algorithm}-{key_size}" if algorithm and key_size else algorithm

                assets.append({
                    "asset_id": asset_id, "scan_id": scan_id,
                    "project": project, "region": region,
                    "resource_type": "SslCertificate", "resource_name": self_link,
                    "resource_url": f"https://console.cloud.google.com/loadbalancing/advanced/sslCertificates/details/{name}?project={project}",
                    "check_module": config.MODULE_CERTS,
                    "asset_role": config.ASSET_ROLE_FINDING,
                    "classification": f"Self-managed Certificate ({algo_str or 'Unknown'})",
                    "pqc_status": config.PQC_CLASSICAL,
                    "algorithm": algo_str, "protocol": None,
                    "raw_config": {k: v for k, v in cert.items() if k != "certificate"},
                })
                findings.append({
                    "scan_id": scan_id, "asset_id": asset_id,
                    "priority": config.PRIORITY_INFORMATIONAL,
                    "finding_type": _algorithm_finding_type(algorithm),
                    "algorithm": algo_str, "protocol": None,
                    "key_size_bits": key_size,
                    "pqc_status": config.PQC_CLASSICAL,
                    "detail": (f"Self-managed certificate '{name}' uses {algo_str or 'unknown algorithm'}. "
                               f"Expires: {expiry.date() if expiry else 'unknown'}."),
                    "remediation": _cert_remediation(algorithm),
                })
                exp = _expiry_finding(expiry, name, asset_id, scan_id)
                if exp:
                    findings.append(exp)

    return assets, findings


# ── Certificate Manager ───────────────────────────────────────────────────────

def _scan_cert_manager(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    try:
        service = build_service("certificatemanager", "v1")
        resp    = service.projects().locations().certificates().list(
            parent=f"projects/{project}/locations/-"
        ).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list Certificate Manager certs", exc)
        return assets, findings

    for cert in resp.get("certificates", []):
        name       = cert.get("name", "unknown")
        short_name = name.split("/")[-1]
        location   = name.split("/")[3] if len(name.split("/")) > 3 else "global"
        is_managed = "managed" in cert
        asset_id   = str(_uuid_mod.uuid4())

        if is_managed:
            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": location,
                "resource_type": "CertificateManagerCert", "resource_name": name,
                "resource_url": f"https://console.cloud.google.com/security/ccm/list/certificates?project={project}",
                "check_module": config.MODULE_CERTS,
                "asset_role": config.ASSET_ROLE_INVENTORY,
                "classification": "Google-managed Certificate",
                "pqc_status": config.PQC_CLASSICAL,
                "algorithm": "ECDSA P-256 (Google-managed)", "protocol": None,
                "raw_config": {k: v for k, v in cert.items() if k != "selfManaged"},
            })
        else:
            pem_data = cert.get("selfManaged", {}).get("pemCertificate")
            algorithm, key_size, expiry = _parse_cert_pem(pem_data)
            algo_str = f"{algorithm}-{key_size}" if algorithm and key_size else algorithm

            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": location,
                "resource_type": "CertificateManagerCert", "resource_name": name,
                "resource_url": f"https://console.cloud.google.com/security/ccm/list/certificates?project={project}",
                "check_module": config.MODULE_CERTS,
                "asset_role": config.ASSET_ROLE_FINDING,
                "classification": f"Self-managed Certificate ({algo_str or 'Unknown'})",
                "pqc_status": config.PQC_CLASSICAL,
                "algorithm": algo_str, "protocol": None,
                "raw_config": {k: v for k, v in cert.items() if k != "selfManaged"},
            })
            findings.append({
                "scan_id": scan_id, "asset_id": asset_id,
                "priority": config.PRIORITY_INFORMATIONAL,
                "finding_type": _algorithm_finding_type(algorithm),
                "algorithm": algo_str, "protocol": None,
                "key_size_bits": key_size,
                "pqc_status": config.PQC_CLASSICAL,
                "detail": (f"Self-managed certificate '{short_name}' uses {algo_str or 'unknown algorithm'}. "
                           f"Expires: {expiry.date() if expiry else 'unknown'}."),
                "remediation": _cert_remediation(algorithm),
            })
            exp = _expiry_finding(expiry, short_name, asset_id, scan_id)
            if exp:
                findings.append(exp)

    return assets, findings


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    a, f = _scan_classic_certs(project, scan_id)
    assets.extend(a); findings.extend(f)
    a, f = _scan_cert_manager(project, scan_id)
    assets.extend(a); findings.extend(f)
    logger.info(f"[{project}] Certs: {len(assets)} assets, {len(findings)} findings.")
    return assets, findings
