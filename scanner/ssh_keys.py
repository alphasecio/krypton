"""
SSH Keys scanner.

Asset roles:
  OS Login enabled            → inventory only (IAM-based auth, ephemeral certs)
  RSA / ECDSA / ED25519 keys  → finding (classical keys, HNDL risk)
  DSA keys                    → finding (weak by classical standards today)
"""

import base64
import hashlib
import logging
import struct
from typing import Dict, List, Optional, Tuple

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


# ── SSH public key parsing ────────────────────────────────────────────────────

def _parse_ssh_pubkey(key_str: str) -> Tuple[str, Optional[int], Optional[str]]:
    parts = key_str.strip().split()
    if len(parts) < 2:
        return "UNKNOWN", None, None
    key_type_str = parts[0].lower()
    b64_data     = parts[1]
    try:
        raw         = base64.b64decode(b64_data)
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(raw).digest()
        ).decode().rstrip("=")
    except Exception:
        fingerprint = None
        raw         = None

    if "rsa"     in key_type_str: return "RSA",     _rsa_size(raw), fingerprint
    if "ecdsa"   in key_type_str: return "ECDSA",   _ecdsa_size(key_type_str), fingerprint
    if "ed25519" in key_type_str: return "ED25519", 256, fingerprint
    if "dsa"     in key_type_str: return "DSA",     1024, fingerprint
    return "UNKNOWN", None, fingerprint


def _rsa_size(raw: Optional[bytes]) -> Optional[int]:
    if not raw:
        return None
    try:
        idx = 0
        def read_chunk():
            nonlocal idx
            length = struct.unpack(">I", raw[idx:idx+4])[0]
            idx += 4
            data = raw[idx:idx+length]
            idx += length
            return data
        read_chunk(); read_chunk()  # algorithm, exponent
        n = read_chunk()            # modulus
        return int.from_bytes(n, "big").bit_length()
    except Exception:
        return None


def _ecdsa_size(key_type_str: str) -> Optional[int]:
    if "256" in key_type_str: return 256
    if "384" in key_type_str: return 384
    if "521" in key_type_str: return 521
    return None


# ── Classification ────────────────────────────────────────────────────────────

def _classify_ssh_key(key_type: str, key_size: Optional[int]):
    """Returns (finding_type, priority, pqc_status, classification)"""
    if key_type == "DSA":
        return (config.FINDING_SSH_RSA, config.PRIORITY_CRITICAL,
                config.PQC_NOT_READY, "SSH Key — DSA (Weak)")
    if key_type == "RSA":
        if key_size and key_size < 2048:
            return (config.FINDING_SSH_RSA, config.PRIORITY_CRITICAL,
                    config.PQC_NOT_READY, f"SSH Key — RSA-{key_size} (Weak)")
        return (config.FINDING_SSH_RSA, config.PRIORITY_HIGH,
                config.PQC_CLASSICAL, f"SSH Key — RSA-{key_size or '?'}")
    if key_type == "ECDSA":
        return (config.FINDING_SSH_ECDSA, config.PRIORITY_HIGH,
                config.PQC_CLASSICAL, f"SSH Key — ECDSA-{key_size or '?'}")
    if key_type == "ED25519":
        return (config.FINDING_SSH_ED25519, config.PRIORITY_MEDIUM,
                config.PQC_CLASSICAL, "SSH Key — ED25519")
    return (config.FINDING_SSH_RSA, config.PRIORITY_MEDIUM,
            config.PQC_CLASSICAL, f"SSH Key — {key_type}")


def _ssh_detail(key_type: str, key_size: Optional[int], scope: str,
                username: Optional[str]) -> str:
    size_str = f"-{key_size}" if key_size else ""
    user_str = f" (user: {username})" if username else ""
    return (f"{scope} SSH key: {key_type}{size_str}{user_str}. "
            "Asymmetric SSH keys are vulnerable to Harvest Now Decrypt Later attacks.")


def _ssh_remediation(key_type: str) -> str:
    if key_type == "DSA":
        return "DSA keys are weak today. Replace immediately with ED25519."
    if key_type == "RSA":
        return ("RSA SSH keys are vulnerable to quantum attacks. "
                "Migrate to ED25519 for new keys. "
                "Plan migration to PQC SSH key types when standardised.")
    if key_type == "ECDSA":
        return ("ECDSA SSH keys are vulnerable to quantum attacks. "
                "Prefer ED25519 for new keys. "
                "Plan migration to PQC SSH key types when available.")
    if key_type == "ED25519":
        return ("ED25519 is current best practice for SSH. "
                "Plan migration to PQC SSH key types when standardised.")
    return "Review SSH key type and replace with ED25519 or stronger."


# ── Metadata helpers ──────────────────────────────────────────────────────────

def _extract_ssh_keys(items: List[Dict]) -> List[Tuple[str, Optional[str]]]:
    result = []
    for item in items:
        if item.get("key") not in ("ssh-keys", "sshKeys"):
            continue
        for line in item.get("value", "").splitlines():
            line = line.strip()
            if not line:
                continue
            username = None
            parts = line.split()
            if parts and ":" in parts[0]:
                username, _, line = line.partition(":")
                line = line.strip()
            result.append((line, username))
    return result


def _os_login_enabled(items: List[Dict]) -> bool:
    return any(
        i.get("key") == "enable-oslogin" and i.get("value", "").lower() == "true"
        for i in items
    )


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    import uuid as _uuid_mod
    service = build_service("compute", "v1")
    assets: List[Dict]   = []
    findings: List[Dict] = []

    # ── Project-level ─────────────────────────────────────────────────────────
    try:
        project_meta = service.projects().get(project=project).execute()
        meta_items   = project_meta.get("commonInstanceMetadata", {}).get("items", [])

        if _os_login_enabled(meta_items):
            asset_id = str(_uuid_mod.uuid4())
            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": "global",
                "resource_type": "Project",
                "resource_name": f"projects/{project}",
                "resource_url": f"https://console.cloud.google.com/compute/metadata?project={project}",
                "check_module": config.MODULE_SSH,
                "asset_role": config.ASSET_ROLE_INVENTORY,
                "classification": "OS Login Authentication",
                "pqc_status": config.PQC_CLASSICAL,
                "algorithm": "OS Login (IAM + ephemeral ECDSA)",
                "protocol": "SSH-2",
                "raw_config": {"osLoginEnabled": True},
            })
            logger.debug(f"[{project}] OS Login enabled — inventoried, no finding.")

        for key_str, username in _extract_ssh_keys(meta_items):
            key_type, key_size, fingerprint = _parse_ssh_pubkey(key_str)
            find_type, priority, pqc_status, classification = _classify_ssh_key(key_type, key_size)
            asset_id = str(_uuid_mod.uuid4())
            algo_str = f"{key_type}-{key_size}" if key_size else key_type

            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": "global",
                "resource_type": "ProjectSshKey",
                "resource_name": f"projects/{project}/metadata/ssh-keys/{fingerprint or 'unknown'}",
                "resource_url": f"https://console.cloud.google.com/compute/metadata?project={project}",
                "check_module": config.MODULE_SSH,
                "asset_role": config.ASSET_ROLE_FINDING,
                "classification": classification,
                "pqc_status": pqc_status,
                "algorithm": algo_str, "protocol": "SSH-2",
                "raw_config": {"key_type": key_type, "key_size": key_size, "username": username},
            })
            findings.append({
                "scan_id": scan_id, "asset_id": asset_id,
                "priority": priority, "finding_type": find_type,
                "algorithm": algo_str, "protocol": "SSH-2",
                "key_size_bits": key_size, "pqc_status": pqc_status,
                "detail": _ssh_detail(key_type, key_size, "Project-level", username),
                "remediation": _ssh_remediation(key_type),
            })

    except Exception as exc:
        _log_api_error(project, "Could not scan project-level SSH keys", exc)

    # ── Instance-level ────────────────────────────────────────────────────────
    try:
        resp = service.instances().aggregatedList(project=project).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list instances for SSH key scan", exc)
        resp = {}

    for zone_key, zone_data in resp.get("items", {}).items():
        zone = zone_key.split("/")[-1]
        for instance in zone_data.get("instances", []):
            inst_name  = instance.get("name", "unknown")
            inst_link  = instance.get("selfLink", "")
            meta_items = instance.get("metadata", {}).get("items", [])

            for key_str, username in _extract_ssh_keys(meta_items):
                key_type, key_size, fingerprint = _parse_ssh_pubkey(key_str)
                find_type, priority, pqc_status, classification = _classify_ssh_key(key_type, key_size)
                asset_id = str(_uuid_mod.uuid4())
                algo_str = f"{key_type}-{key_size}" if key_size else key_type

                assets.append({
                    "asset_id": asset_id, "scan_id": scan_id,
                    "project": project, "region": zone,
                    "resource_type": "InstanceSshKey",
                    "resource_name": f"{inst_link}/ssh-keys/{fingerprint or 'unknown'}",
                    "resource_url": f"https://console.cloud.google.com/compute/instancesDetail/zones/{zone}/instances/{inst_name}?project={project}",
                    "check_module": config.MODULE_SSH,
                    "asset_role": config.ASSET_ROLE_FINDING,
                    "classification": classification,
                    "pqc_status": pqc_status,
                    "algorithm": algo_str, "protocol": "SSH-2",
                    "raw_config": {"instance": inst_name, "zone": zone,
                                   "key_type": key_type, "key_size": key_size},
                })
                findings.append({
                    "scan_id": scan_id, "asset_id": asset_id,
                    "priority": priority, "finding_type": find_type,
                    "algorithm": algo_str, "protocol": "SSH-2",
                    "key_size_bits": key_size, "pqc_status": pqc_status,
                    "detail": _ssh_detail(key_type, key_size, f"Instance '{inst_name}' ({zone})", username),
                    "remediation": _ssh_remediation(key_type),
                })

    logger.info(f"[{project}] SSH: {len(assets)} assets, {len(findings)} findings.")
    return assets, findings
