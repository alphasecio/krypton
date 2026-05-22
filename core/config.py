"""
App-wide configuration.
Change APP_NAME and APP_DESCRIPTION here — nowhere else.
"""

APP_NAME        = "krypton"
APP_VERSION     = "0.1.0"
APP_DESCRIPTION = "Google Cloud PQC Readiness Scanner"

# ── Priority levels ───────────────────────────────────────────────────────────
PRIORITY_CRITICAL       = "CRITICAL"
PRIORITY_HIGH           = "HIGH"
PRIORITY_MEDIUM         = "MEDIUM"
PRIORITY_LOW            = "LOW"
PRIORITY_INFORMATIONAL  = "INFORMATIONAL"

PRIORITY_ORDER = [
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    PRIORITY_MEDIUM,
    PRIORITY_LOW,
    PRIORITY_INFORMATIONAL,
]

# ── PQC status values ─────────────────────────────────────────────────────────
PQC_NOT_READY   = "NOT_READY"       # weak config, broken or missing policy
PQC_CLASSICAL   = "CLASSICAL"       # strong today, vulnerable post Q-Day (HNDL)
PQC_CAPABLE     = "PQC_CAPABLE"     # optimally configured; PQC auto-enabled when Google ships
PQC_READY       = "PQC_READY"       # already using ML-KEM / ML-DSA
PQC_SAFE        = "SAFE"            # symmetric AES-256/HMAC — quantum-safe by design

# ── Finding type identifiers (only for findings that ARE written) ─────────────
# TLS
FINDING_DEFAULT_SSL_POLICY  = "DEFAULT_SSL_POLICY"   # no policy attached (Google default)
FINDING_LEGACY_TLS          = "LEGACY_TLS"           # TLS 1.0 / 1.1
FINDING_WEAK_CIPHER         = "WEAK_CIPHER"          # COMPATIBLE or weak CUSTOM ciphers
FINDING_TLS_RESTRICTED      = "TLS_RESTRICTED"       # MODERN/FIPS/RESTRICTED+1.2 — suboptimal

# Certificates
FINDING_CERT_RSA            = "CERT_RSA_CLASSICAL"
FINDING_CERT_ECDSA          = "CERT_ECDSA_CLASSICAL"
FINDING_CERT_EXPIRING       = "CERT_EXPIRING_SOON"
FINDING_CERT_EXPIRED        = "CERT_EXPIRED"

# KMS / encryption
FINDING_KMS_RSA             = "KMS_RSA_CLASSICAL"
FINDING_KMS_EC              = "KMS_EC_CLASSICAL"
FINDING_NO_CMEK             = "NO_CMEK"

# SSH
FINDING_SSH_RSA             = "SSH_RSA_CLASSICAL"
FINDING_SSH_ECDSA           = "SSH_ECDSA_CLASSICAL"
FINDING_SSH_ED25519         = "SSH_ED25519_CLASSICAL"

# ── Asset roles ───────────────────────────────────────────────────────────────
ASSET_ROLE_FINDING   = "finding"    # has an associated finding
ASSET_ROLE_INVENTORY = "inventory"  # catalogued only, no finding

# ── Check modules ─────────────────────────────────────────────────────────────
MODULE_TLS   = "tls_policies"
MODULE_CERTS = "certificates"
MODULE_KMS   = "kms_keys"
MODULE_SSH   = "ssh_keys"

ALL_MODULES = [MODULE_TLS, MODULE_CERTS, MODULE_KMS, MODULE_SSH]

# ── Scan status ───────────────────────────────────────────────────────────────
SCAN_RUNNING  = "running"
SCAN_COMPLETE = "complete"
SCAN_FAILED   = "failed"

# ── Weak TLS 1.2 cipher suites (IANA names used by Google CUSTOM SSL policies) ──
WEAK_CIPHERS = {
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

# ── KMS algorithm families ────────────────────────────────────────────────────
KMS_SYMMETRIC_ALGORITHMS = {
    "GOOGLE_SYMMETRIC_ENCRYPTION",
    "AES_128_GCM", "AES_256_GCM",
    "AES_128_CBC", "AES_256_CBC",
    "AES_128_CTR", "AES_256_CTR",
}

KMS_HMAC_ALGORITHMS = {
    "HMAC_SHA256", "HMAC_SHA1", "HMAC_SHA384",
    "HMAC_SHA512", "HMAC_SHA256_NO_PREFIX",
}

KMS_RSA_ALGORITHMS = {
    "RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256",
    "RSA_SIGN_PSS_4096_SHA256", "RSA_SIGN_PSS_4096_SHA512",
    "RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256",
    "RSA_SIGN_PKCS1_4096_SHA256", "RSA_SIGN_PKCS1_4096_SHA512",
    "RSA_SIGN_RAW_PKCS1_2048", "RSA_SIGN_RAW_PKCS1_3072",
    "RSA_SIGN_RAW_PKCS1_4096",
    "RSA_DECRYPT_OAEP_2048_SHA256", "RSA_DECRYPT_OAEP_3072_SHA256",
    "RSA_DECRYPT_OAEP_4096_SHA256", "RSA_DECRYPT_OAEP_4096_SHA512",
    "RSA_DECRYPT_OAEP_2048_SHA1",   "RSA_DECRYPT_OAEP_3072_SHA1",
    "RSA_DECRYPT_OAEP_4096_SHA1",
}

KMS_EC_ALGORITHMS = {
    "EC_SIGN_P256_SHA256", "EC_SIGN_P384_SHA384",
    "EC_SIGN_ED25519",     "EC_SIGN_SECP256K1_SHA256",
}

KMS_PQC_ALGORITHMS = {
    "ML_KEM_768", "ML_KEM_1024",
    "ML_DSA_65",  "ML_DSA_87",
    "SLH_DSA_SHA2_128S",
}

# ── Certificate expiry warning threshold ─────────────────────────────────────
CERT_EXPIRY_WARNING_DAYS = 30

# ── Output file names ─────────────────────────────────────────────────────────
DB_FILENAME         = "krypton.db"
REPORT_FILENAME_TPL = "{app_name}_{timestamp}_report.html"
