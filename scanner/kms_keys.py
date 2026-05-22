"""
KMS Keys scanner.

Asset roles:
  Symmetric / HMAC / PQC keys → inventory only (quantum-safe or already PQC)
  RSA / EC keys               → finding (classical, HNDL risk)
  CMEK-protected resources    → inventory only
  No-CMEK resources           → finding (grouped per project per resource type)
"""

import logging
import uuid as _uuid_mod
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from core import config
from core.auth import build_service, get_credentials

logger = logging.getLogger(__name__)


def _log_api_error(project: str, context: str, exc: Exception) -> None:
    msg = str(exc)
    expected = ("has not been used", "has not enabled", "SERVICE_DISABLED",
                 "is disabled", "accessNotConfigured", "PERMISSION_DENIED")
    if any(s in msg for s in expected):
        logger.debug(f"[{project}] {context} — API not enabled, skipping.")
    else:
        logger.warning(f"[{project}] {context}: {exc}")


# ── Algorithm classification ──────────────────────────────────────────────────

def _classify_algorithm(algorithm: str):
    """Returns (priority, pqc_status, asset_role, classification, key_size)"""
    if algorithm in config.KMS_PQC_ALGORITHMS:
        return (config.PRIORITY_INFORMATIONAL, config.PQC_READY,
                config.ASSET_ROLE_INVENTORY,
                f"PQC Key — {_algo_label(algorithm)}", _pqc_size(algorithm))

    if algorithm in config.KMS_SYMMETRIC_ALGORITHMS or algorithm in config.KMS_HMAC_ALGORITHMS:
        return (config.PRIORITY_INFORMATIONAL, config.PQC_SAFE,
                config.ASSET_ROLE_INVENTORY,
                f"Symmetric Key — {_algo_label(algorithm)}", 256)

    if algorithm in config.KMS_RSA_ALGORITHMS:
        size = _rsa_size(algorithm)
        return (config.PRIORITY_HIGH, config.PQC_CLASSICAL,
                config.ASSET_ROLE_FINDING,
                f"RSA Key — {_algo_label(algorithm)}", size)

    if algorithm in config.KMS_EC_ALGORITHMS:
        size = _ec_size(algorithm)
        return (config.PRIORITY_HIGH, config.PQC_CLASSICAL,
                config.ASSET_ROLE_FINDING,
                f"EC Key — {_algo_label(algorithm)}", size)

    # Unknown — conservative
    return (config.PRIORITY_MEDIUM, config.PQC_CLASSICAL,
            config.ASSET_ROLE_FINDING, f"Unknown Key — {algorithm}", None)


def _algo_label(algorithm: str) -> str:
    labels = {
        "GOOGLE_SYMMETRIC_ENCRYPTION": "AES-256",
        "RSA_DECRYPT_OAEP_2048_SHA256": "RSA-2048", "RSA_DECRYPT_OAEP_3072_SHA256": "RSA-3072",
        "RSA_DECRYPT_OAEP_4096_SHA256": "RSA-4096", "RSA_SIGN_PKCS1_2048_SHA256": "RSA-2048",
        "RSA_SIGN_PKCS1_3072_SHA256": "RSA-3072",   "RSA_SIGN_PKCS1_4096_SHA256": "RSA-4096",
        "RSA_SIGN_PSS_2048_SHA256": "RSA-2048 (PSS)", "RSA_SIGN_PSS_3072_SHA256": "RSA-3072 (PSS)",
        "RSA_SIGN_PSS_4096_SHA256": "RSA-4096 (PSS)",
        "EC_SIGN_P256_SHA256": "ECDSA P-256", "EC_SIGN_P384_SHA384": "ECDSA P-384",
        "EC_SIGN_ED25519": "Ed25519",          "EC_SIGN_SECP256K1_SHA256": "ECDSA secp256k1",
        "HMAC_SHA256": "HMAC-SHA256",          "HMAC_SHA512": "HMAC-SHA512",
        "ML_KEM_768": "ML-KEM-768",            "ML_KEM_1024": "ML-KEM-1024",
        "ML_DSA_65": "ML-DSA-65",              "ML_DSA_87": "ML-DSA-87",
    }
    return labels.get(algorithm, algorithm)


def _rsa_size(algorithm: str) -> Optional[int]:
    for size in (4096, 3072, 2048):
        if str(size) in algorithm: return size
    return None

def _ec_size(algorithm: str) -> Optional[int]:
    if "P256" in algorithm or "SECP256" in algorithm: return 256
    if "P384" in algorithm: return 384
    if "ED25519" in algorithm: return 256
    return None

def _pqc_size(algorithm: str) -> Optional[int]:
    for n in ("1024", "768", "87", "65", "128"):
        if n in algorithm: return int(n)
    return None


def _kms_remediation(algorithm: str, pqc_status: str) -> Optional[str]:
    if pqc_status in (config.PQC_SAFE, config.PQC_READY):
        return None
    label = _algo_label(algorithm)
    if algorithm in config.KMS_RSA_ALGORITHMS:
        return (f"Key uses {label}, vulnerable to quantum attacks. "
                "Plan migration to ML-KEM (encryption) or ML-DSA (signing) "
                "when Cloud KMS PQC support is GA. Prioritise keys protecting "
                "long-lived sensitive data.")
    if algorithm in config.KMS_EC_ALGORITHMS:
        return (f"Key uses {label}, vulnerable to quantum attacks. "
                "Plan migration to ML-DSA for signing use cases.")
    return "Review key algorithm."


# ── KMS enumeration ───────────────────────────────────────────────────────────

def _kms_api_enabled(kms_service, project: str) -> bool:
    """Probe global location to check if KMS API is enabled. Fast-fail if not."""
    try:
        kms_service.projects().locations().keyRings().list(
            parent=f"projects/{project}/locations/global"
        ).execute()
        return True
    except Exception as exc:
        msg = str(exc)
        expected = ("has not been used", "has not enabled", "SERVICE_DISABLED", "is disabled")
        if any(s in msg for s in expected):
            logger.debug(f"[{project}] Cloud KMS API not enabled — skipping.")
            return False
        if "KMS_RESOURCE_NOT_FOUND" in msg or "404" in msg or "PERMISSION_DENIED" in msg:
            return True  # API enabled, just no rings in global
        logger.debug(f"[{project}] KMS API check: {exc}")
        return False


def _list_kms_locations(kms_service, project: str) -> List[str]:
    """Enumerate all KMS locations. '-' wildcard only works on gRPC, not REST."""
    locations = []
    try:
        resp = kms_service.projects().locations().list(
            name=f"projects/{project}"
        ).execute()
        locations = [loc["name"] for loc in resp.get("locations", []) if loc.get("name")]
        logger.debug(f"[{project}] KMS locations: {len(locations)}")
    except Exception as exc:
        logger.debug(f"[{project}] Could not list KMS locations: {exc}")
    return locations


def _scan_location_for_keys(args: Tuple) -> List[Tuple]:
    """Scan one KMS location. Builds its own service for thread safety."""
    from googleapiclient import discovery
    location, creds, project = args
    results = []
    try:
        svc = discovery.build("cloudkms", "v1", credentials=creds, cache_discovery=False)
        kr_resp = svc.projects().locations().keyRings().list(parent=location).execute()
    except Exception:
        return results

    for key_ring in kr_resp.get("keyRings", []):
        kr_name = key_ring["name"]
        try:
            ck_resp = svc.projects().locations().keyRings().cryptoKeys().list(
                parent=kr_name
            ).execute()
        except Exception as exc:
            logger.warning(f"[{project}] Could not list crypto keys in {kr_name}: {exc}")
            continue

        for crypto_key in ck_resp.get("cryptoKeys", []):
            ck_name = crypto_key["name"]
            try:
                v_resp = (svc.projects().locations().keyRings().cryptoKeys()
                          .cryptoKeyVersions()
                          .list(parent=ck_name, filter="state=ENABLED")
                          .execute())
            except Exception as exc:
                logger.warning(f"[{project}] Could not list versions for {ck_name}: {exc}")
                continue
            for version in v_resp.get("cryptoKeyVersions", []):
                results.append((key_ring, crypto_key, version))
    return results


def _iter_key_versions(kms_service, project: str) -> List[Tuple]:
    """Return all ENABLED key versions. Scans locations concurrently."""
    if not _kms_api_enabled(kms_service, project):
        return []
    locations = _list_kms_locations(kms_service, project)
    if not locations:
        return []

    creds, _ = get_credentials()
    results  = []
    logger.debug(f"[{project}] Scanning {len(locations)} KMS locations concurrently.")
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_scan_location_for_keys, (loc, creds, project))
                   for loc in locations]
        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as exc:
                logger.debug(f"[{project}] Location scan error: {exc}")
    return results


# ── CMEK coverage ─────────────────────────────────────────────────────────────

def _check_gcs_cmek(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    try:
        storage = build_service("storage", "v1")
        resp = storage.buckets().list(
            project=project, fields="items(name,selfLink,encryption)"
        ).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list GCS buckets", exc)
        return assets, findings

    no_cmek, cmek = [], []
    for bucket in resp.get("items", []):
        name = bucket.get("name", "")
        cmek_key = bucket.get("encryption", {}).get("defaultKmsKeyName")
        (cmek if cmek_key else no_cmek).append((name, cmek_key))

    for name, cmek_key in cmek:
        asset_id = str(_uuid_mod.uuid4())
        assets.append({
            "asset_id": asset_id, "scan_id": scan_id,
            "project": project, "region": "global",
            "resource_type": "GcsBucket",
            "resource_name": f"gs://{name}",
            "resource_url": f"https://console.cloud.google.com/storage/browser/{name}?project={project}",
            "check_module": config.MODULE_KMS,
            "asset_role": config.ASSET_ROLE_INVENTORY,
            "classification": "Customer-managed Encryption (GCS)",
            "pqc_status": config.PQC_SAFE,
            "algorithm": "AES-256 (CMEK)", "protocol": None,
            "raw_config": {"name": name, "cmekKey": cmek_key},
        })

    if no_cmek:
        asset_id    = str(_uuid_mod.uuid4())
        names       = [n for n, _ in no_cmek]
        bucket_list = ", ".join(names[:10])
        suffix      = f" (+{len(names)-10} more)" if len(names) > 10 else ""
        assets.append({
            "asset_id": asset_id, "scan_id": scan_id,
            "project": project, "region": "global",
            "resource_type": "GcsBucket",
            "resource_name": f"projects/{project}/buckets (no CMEK)",
            "resource_url": f"https://console.cloud.google.com/storage/browser?project={project}",
            "check_module": config.MODULE_KMS,
            "asset_role": config.ASSET_ROLE_FINDING,
            "classification": "Unmanaged Encryption (GCS)",
            "pqc_status": config.PQC_SAFE,
            "algorithm": "AES-256 (Google-managed)", "protocol": None,
            "raw_config": {"buckets_without_cmek": names},
        })
        findings.append({
            "scan_id": scan_id, "asset_id": asset_id,
            "priority": config.PRIORITY_LOW,
            "finding_type": config.FINDING_NO_CMEK,
            "algorithm": "AES-256 (Google-managed)", "protocol": None,
            "key_size_bits": 256, "pqc_status": config.PQC_SAFE,
            "detail": (f"{len(names)} GCS bucket(s) use Google-managed encryption "
                       f"(no CMEK): {bucket_list}{suffix}."),
            "remediation": "Assign a Cloud KMS CMEK key. Ideal for future PQC key migration.",
        })
    return assets, findings


def _check_bq_cmek(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    try:
        bq   = build_service("bigquery", "v2")
        resp = bq.datasets().list(projectId=project).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list BigQuery datasets", exc)
        return assets, findings

    no_cmek, cmek = [], []
    for ds_ref in resp.get("datasets", []):
        ds_id = ds_ref.get("datasetReference", {}).get("datasetId", "")
        try:
            ds = bq.datasets().get(projectId=project, datasetId=ds_id).execute()
        except Exception as exc:
            logger.warning(f"[{project}] Could not get BQ dataset {ds_id}: {exc}")
            continue
        cmek_key = ds.get("defaultEncryptionConfiguration", {}).get("kmsKeyName")
        (cmek if cmek_key else no_cmek).append((ds_id, cmek_key, ds))

    for ds_id, cmek_key, ds in cmek:
        asset_id = str(_uuid_mod.uuid4())
        assets.append({
            "asset_id": asset_id, "scan_id": scan_id,
            "project": project, "region": ds.get("location", "unknown"),
            "resource_type": "BigQueryDataset",
            "resource_name": f"projects/{project}/datasets/{ds_id}",
            "resource_url": f"https://console.cloud.google.com/bigquery?project={project}&d={ds_id}",
            "check_module": config.MODULE_KMS,
            "asset_role": config.ASSET_ROLE_INVENTORY,
            "classification": "Customer-managed Encryption (BigQuery)",
            "pqc_status": config.PQC_SAFE,
            "algorithm": "AES-256 (CMEK)", "protocol": None,
            "raw_config": {"datasetId": ds_id, "cmekKey": cmek_key},
        })

    if no_cmek:
        asset_id = str(_uuid_mod.uuid4())
        ds_ids   = [d for d, _, _ in no_cmek]
        ds_list  = ", ".join(ds_ids[:10])
        suffix   = f" (+{len(ds_ids)-10} more)" if len(ds_ids) > 10 else ""
        assets.append({
            "asset_id": asset_id, "scan_id": scan_id,
            "project": project, "region": "global",
            "resource_type": "BigQueryDataset",
            "resource_name": f"projects/{project}/datasets (no CMEK)",
            "resource_url": f"https://console.cloud.google.com/bigquery?project={project}",
            "check_module": config.MODULE_KMS,
            "asset_role": config.ASSET_ROLE_FINDING,
            "classification": "Unmanaged Encryption (BigQuery)",
            "pqc_status": config.PQC_SAFE,
            "algorithm": "AES-256 (Google-managed)", "protocol": None,
            "raw_config": {"datasets_without_cmek": ds_ids},
        })
        findings.append({
            "scan_id": scan_id, "asset_id": asset_id,
            "priority": config.PRIORITY_LOW,
            "finding_type": config.FINDING_NO_CMEK,
            "algorithm": "AES-256 (Google-managed)", "protocol": None,
            "key_size_bits": 256, "pqc_status": config.PQC_SAFE,
            "detail": (f"{len(ds_ids)} BigQuery dataset(s) use Google-managed "
                       f"encryption (no CMEK): {ds_list}{suffix}."),
            "remediation": "Assign a Cloud KMS CMEK key. Ideal for future PQC key migration.",
        })
    return assets, findings


def _check_sql_cmek(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    assets, findings = [], []
    try:
        sql  = build_service("sqladmin", "v1")
        resp = sql.instances().list(project=project).execute()
    except Exception as exc:
        _log_api_error(project, "Could not list Cloud SQL instances", exc)
        return assets, findings

    for instance in resp.get("items", []):
        name     = instance.get("name", "")
        region   = instance.get("region", "unknown")
        cmek_key = instance.get("diskEncryptionConfiguration", {}).get("kmsKeyName")
        asset_id = str(_uuid_mod.uuid4())

        if cmek_key:
            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": region,
                "resource_type": "CloudSqlInstance",
                "resource_name": f"projects/{project}/instances/{name}",
                "resource_url": f"https://console.cloud.google.com/sql/instances/{name}/overview?project={project}",
                "check_module": config.MODULE_KMS,
                "asset_role": config.ASSET_ROLE_INVENTORY,
                "classification": "Customer-managed Encryption (Cloud SQL)",
                "pqc_status": config.PQC_SAFE,
                "algorithm": "AES-256 (CMEK)", "protocol": None,
                "raw_config": {"name": name, "cmekKey": cmek_key},
            })
        else:
            assets.append({
                "asset_id": asset_id, "scan_id": scan_id,
                "project": project, "region": region,
                "resource_type": "CloudSqlInstance",
                "resource_name": f"projects/{project}/instances/{name}",
                "resource_url": f"https://console.cloud.google.com/sql/instances/{name}/overview?project={project}",
                "check_module": config.MODULE_KMS,
                "asset_role": config.ASSET_ROLE_FINDING,
                "classification": "Unmanaged Encryption (Cloud SQL)",
                "pqc_status": config.PQC_SAFE,
                "algorithm": "AES-256 (Google-managed)", "protocol": None,
                "raw_config": {"name": name},
            })
            findings.append({
                "scan_id": scan_id, "asset_id": asset_id,
                "priority": config.PRIORITY_LOW,
                "finding_type": config.FINDING_NO_CMEK,
                "algorithm": "AES-256 (Google-managed)", "protocol": None,
                "key_size_bits": 256, "pqc_status": config.PQC_SAFE,
                "detail": f"Cloud SQL instance '{name}' ({region}) uses Google-managed encryption (no CMEK).",
                "remediation": "Enable CMEK. Ideal for future PQC key migration.",
            })
    return assets, findings


# ── Main scanner entry point ──────────────────────────────────────────────────

def scan(project: str, scan_id: str) -> Tuple[List[Dict], List[Dict]]:
    kms_service = build_service("cloudkms", "v1")
    assets: List[Dict]   = []
    findings: List[Dict] = []

    for key_ring, crypto_key, version in _iter_key_versions(kms_service, project):
        algorithm    = version.get("algorithm", "UNKNOWN")
        protection   = version.get("protectionLevel", "SOFTWARE")
        version_name = version.get("name", "")
        ck_name      = crypto_key.get("name", "")
        purpose      = crypto_key.get("purpose", "")

        priority, pqc_status, asset_role, classification, key_size = (
            _classify_algorithm(algorithm)
        )
        algo_label = _algo_label(algorithm)
        parts      = ck_name.split("/")
        region     = parts[3] if len(parts) > 3 else "global"
        asset_id   = str(_uuid_mod.uuid4())

        assets.append({
            "asset_id": asset_id, "scan_id": scan_id,
            "project": project, "region": region,
            "resource_type": "CryptoKeyVersion",
            "resource_name": version_name,
            "resource_url": f"https://console.cloud.google.com/security/kms?project={project}",
            "check_module": config.MODULE_KMS,
            "asset_role": asset_role,
            "classification": classification,
            "pqc_status": pqc_status,
            "algorithm": algo_label, "protocol": None,
            "raw_config": {**crypto_key, "_version": version, "_protection": protection},
        })

        if asset_role == config.ASSET_ROLE_FINDING:
            rem = _kms_remediation(algorithm, pqc_status)
            findings.append({
                "scan_id": scan_id, "asset_id": asset_id,
                "priority": priority,
                "finding_type": (config.FINDING_KMS_RSA
                                 if algorithm in config.KMS_RSA_ALGORITHMS
                                 else config.FINDING_KMS_EC),
                "algorithm": algo_label, "protocol": None,
                "key_size_bits": key_size, "pqc_status": pqc_status,
                "detail": (f"KMS key '{ck_name.split('/')[-1]}' uses {algo_label} "
                           f"(purpose: {purpose}, protection: {protection})."),
                "remediation": rem,
            })

    for check_fn in (_check_gcs_cmek, _check_bq_cmek, _check_sql_cmek):
        a, f = check_fn(project, scan_id)
        assets.extend(a); findings.extend(f)

    logger.info(f"[{project}] KMS: {len(assets)} assets, {len(findings)} findings.")
    return assets, findings
