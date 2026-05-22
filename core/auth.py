"""
Authentication — Application Default Credentials only.
Works with:
  - gcloud auth application-default login  (Cloud Shell / local dev)
  - Attached service account               (Cloud Run / GCE)
  - Workload Identity                      (GKE)
No service account key files. No hardcoded credentials.
"""

import google.auth
import google.auth.transport.requests
from googleapiclient import discovery

# Scopes required across all modules
_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform.read-only",
]


def get_credentials():
    """
    Return ADC credentials, refreshed and scoped.
    Raises google.auth.exceptions.DefaultCredentialsError if no ADC found.
    """
    creds, project = google.auth.default(scopes=_SCOPES)
    # Ensure token is fresh
    request = google.auth.transport.requests.Request()
    if not creds.valid:
        creds.refresh(request)
    return creds, project


def build_service(service_name: str, version: str):
    """
    Build a Google API discovery client for the given service.
    Uses ADC — no explicit credential passing needed by callers.
    """
    creds, _ = get_credentials()
    return discovery.build(service_name, version, credentials=creds, cache_discovery=False)
