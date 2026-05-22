# Krypton

**Google Cloud Post-Quantum Cryptography (PQC) Readiness Scanner**

Krypton inventories cryptographic assets across your Google Cloud environment and identifies configurations that are not ready for the post-quantum era. It produces a self-contained HTML report and a persistent SQLite database for trend tracking.

![Krypton PQC Readiness Report](/static/krypton-pqc.png)


## What it scans (cryptographic assets)

| Module | Assets | Findings |
|------------------|---|---|
| **TLS Policies** | HTTPS and SSL Proxy load balancers | Missing SSL policy, legacy TLS (1.0/1.1), weak ciphers, suboptimal profiles |
| **Certificates** | Classic SSL certs, Certificate Manager | Classical RSA/ECDSA keys (harvest risk), expiry warnings |
| **KMS/HSM Keys** | Cloud KMS key versions | Classical RSA/EC keys, resources without CMEK |
| **SSH Keys**     | Project and instance metadata keys, OS Login | RSA/ECDSA/DSA keys in metadata |


## What it reports (PQC status)

| Status | Meaning |
|---|---|
| **PQC Ready** | Already using ML-KEM or ML-DSA (Cloud KMS preview) |
| **PQC Capable** | RESTRICTED + TLS 1.3 — optimally configured, PQC auto-enabled when Google ships it |
| **Quantum-Safe** | AES-256 / HMAC — symmetric, quantum-resistant by design |
| **Classical** | Strong today, vulnerable post Q-Day (harvest now, decrypt later risk) |
| **Not Ready** | Weak or missing configuration, needs immediate attention |


## Prerequisites

- Google Cloud Shell (or any environment with `gcloud` authenticated)
- ADC configured: `gcloud auth application-default login`
- Python 3.9+


## Setup

### Installation

```bash
git clone https://github.com/alphasecio/krypton
cd krypton
chmod +x setup.sh

# Single project
./setup.sh --project your-project-id

# Org-wide
./setup.sh --org your-org-id --billing-project your-project-id
```

`setup.sh` enables required APIs, grants minimum IAM roles to your active identity, and creates a Python virtualenv.

### IAM roles granted

| Role | Purpose |
|---|---|
| `roles/compute.viewer` | Load balancers, SSL policies, instances, project metadata |
| `roles/certificatemanager.viewer` | Certificate Manager |
| `roles/cloudkms.viewer` | KMS key rings, keys, versions |
| `roles/storage.legacyBucketReader` | GCS bucket encryption metadata |
| `roles/bigquery.metadataViewer` | BigQuery dataset encryption config |
| `roles/cloudsql.viewer` | Cloud SQL instance CMEK status |
| `roles/resourcemanager.organizationViewer` | Project enumeration (org mode only) |


## Running

```bash
source .venv/bin/activate

# Scan a single project
python krypton.py --project your-project-id

# Scan all projects in an org
python krypton.py --org your-org-id

# Skip HTML report (DB only)
python krypton.py --project your-project-id --no-report
```

Each run appends a new scan record to `krypton.db` and writes a timestamped HTML report:

```
krypton.db
krypton_20260521_103000_report.html
```


## Report

The HTML report is fully self-contained — no external dependencies, works offline. It includes:

- **Three summary cards**: Crypto assets breakdown, PQC status distribution, findings by severity
- **Findings section**: All actionable issues, sorted by severity
- **Crypto Assets section**: Complete cryptographic inventory grouped by module


## Limitations

- **No PQC-specific SSL policy attribute on Google Cloud** — Google does not yet expose ML-KEM key exchange as a customer-configurable SSL policy option. `PQC Capable` (RESTRICTED + TLS 1.3) is the closest achievable signal; actual PQC key exchange happens transparently at the GFE layer when Google enables it.
- **Control-plane only** — Krypton reads Google Cloud API configuration. It does not perform active TLS handshakes or scan application-layer cryptography, container images, or IaC.
- **KMS PQC algorithms** — ML-KEM and ML-DSA in Cloud KMS are in preview. `PQC Ready` findings will appear when these are in use.


## Disclaimer

Krypton is an independent open-source project with no affiliation to Google LLC or any other vendor. It is provided for educational and informational purposes only. Scan results may be incomplete, inaccurate, or out of date — do not rely on them as a substitute for a professional security assessment. The author accepts no liability for decisions made based on this tool's output. Use at your own risk.
