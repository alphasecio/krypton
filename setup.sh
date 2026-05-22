#!/usr/bin/env bash
# setup.sh — prepares a GCP project or org for a scan run.
# Enables required APIs, grants minimum IAM roles to the active identity,
# and installs Python dependencies in a virtualenv.
#
# Usage:
#   ./setup.sh --project my-project-id
#   ./setup.sh --org 123456789
#   ./setup.sh --org 123456789 --billing-project my-project-id
#
# The identity granted roles is the currently active gcloud account.
# Run in Cloud Shell or any environment with gcloud authenticated.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
PROJECT_ID=""
ORG_ID=""
BILLING_PROJECT="${BILLING_PROJECT:-}"
SKIP_IAM=false
SKIP_DEPS=false
VENV_DIR=".venv"

# ── Arg parsing ───────────────────────────────────────────────────────────────
usage() {
  echo "Usage: $0 --project PROJECT_ID | --org ORG_ID [--billing-project PROJECT_ID] [--skip-iam] [--skip-deps]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)          PROJECT_ID="$2";       shift 2 ;;
    --org)              ORG_ID="$2";            shift 2 ;;
    --billing-project)  BILLING_PROJECT="$2";   shift 2 ;;
    --skip-iam)         SKIP_IAM=true;          shift   ;;
    --skip-deps)        SKIP_DEPS=true;         shift   ;;
    *) usage ;;
  esac
done

if [[ -z "$PROJECT_ID" && -z "$ORG_ID" ]]; then usage; fi
if [[ -n "$PROJECT_ID" && -n "$ORG_ID" ]]; then
  echo "Error: provide --project or --org, not both."
  exit 1
fi

# ── Active identity ───────────────────────────────────────────────────────────
ACTIVE_ACCOUNT=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1)
if [[ -z "$ACTIVE_ACCOUNT" ]]; then
  echo "Error: no active gcloud account found. Run: gcloud auth application-default login"
  exit 1
fi
echo "Active account : $ACTIVE_ACCOUNT"

# ── APIs to enable ────────────────────────────────────────────────────────────
REQUIRED_APIS=(
  compute.googleapis.com
  certificatemanager.googleapis.com
  cloudkms.googleapis.com
  storage.googleapis.com
  bigquery.googleapis.com
  sqladmin.googleapis.com
  cloudresourcemanager.googleapis.com
  iam.googleapis.com
)

# ── IAM roles (project-level) ─────────────────────────────────────────────────
PROJECT_ROLES=(
  roles/compute.viewer
  roles/certificatemanager.viewer
  roles/cloudkms.viewer
  roles/storage.legacyBucketReader
  roles/bigquery.metadataViewer
  roles/cloudsql.viewer
)

# ── IAM roles (org-level) ─────────────────────────────────────────────────────
ORG_ROLES=(
  roles/compute.viewer
  roles/certificatemanager.viewer
  roles/cloudkms.viewer
  roles/storage.legacyBucketReader
  roles/bigquery.metadataViewer
  roles/cloudsql.viewer
  roles/resourcemanager.organizationViewer
)

# ── Helpers ───────────────────────────────────────────────────────────────────
step() { echo -e "\n\033[1;36m▶ $*\033[0m"; }
ok()   { echo -e "  \033[1;32m✓\033[0m $*"; }
warn() { echo -e "  \033[1;33m⚠\033[0m $*"; }

# ── Enable APIs ───────────────────────────────────────────────────────────────
enable_apis() {
  local proj="$1"
  step "Enabling required APIs on project: $proj"
  for api in "${REQUIRED_APIS[@]}"; do
    # Check if already enabled first
    if gcloud services list --project="$proj" --filter="name:$api" \
        --format="value(name)" 2>/dev/null | grep -q "$api"; then
      ok "$api (already enabled)"
    elif gcloud services enable "$api" --project="$proj" --quiet >/dev/null 2>&1; then
      ok "$api"
    else
      warn "Could not enable $api — check roles/serviceusage.serviceUsageAdmin."
    fi
  done
}

# ── Grant project roles ───────────────────────────────────────────────────────
grant_project_roles() {
  local proj="$1"
  step "Granting IAM roles on project: $proj"
  for role in "${PROJECT_ROLES[@]}"; do
    # add-iam-policy-binding is idempotent — exit 0 means granted or already present
    if gcloud projects add-iam-policy-binding "$proj" \
        --member="user:$ACTIVE_ACCOUNT" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null 2>&1; then
      ok "$role"
    else
      warn "$role — failed. Check you have roles/resourcemanager.projectIamAdmin."
    fi
  done
}

# ── Grant org roles ───────────────────────────────────────────────────────────
grant_org_roles() {
  local org="$1"
  step "Granting IAM roles on organisation: $org"
  for role in "${ORG_ROLES[@]}"; do
    # add-iam-policy-binding is idempotent — exit 0 means granted or already present
    if gcloud organizations add-iam-policy-binding "$org" \
        --member="user:$ACTIVE_ACCOUNT" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null 2>&1; then
      ok "$role"
    else
      warn "$role — failed. Check you have roles/resourcemanager.organizationAdmin."
    fi
  done
}

# ── Python virtualenv + dependencies ──────────────────────────────────────────
install_deps() {
  step "Setting up Python virtualenv: $VENV_DIR"

  if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Virtualenv created"
  else
    ok "Virtualenv already exists"
  fi

  # Activate and install — isolated from Cloud Shell system packages
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  pip install --quiet --upgrade pip
  pip install --quiet -r requirements.txt
  ok "Dependencies installed in $VENV_DIR"

  deactivate
}

# ── Verify ADC ────────────────────────────────────────────────────────────────
verify_adc() {
  step "Verifying Application Default Credentials"
  if gcloud auth application-default print-access-token &>/dev/null; then
    ok "ADC is configured"
  else
    warn "ADC not found. Run: gcloud auth application-default login"
    warn "The scanner uses ADC for API calls — this must be set before running."
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
if [[ -n "$PROJECT_ID" ]]; then
  echo "Scope: project ($PROJECT_ID)"
  enable_apis "$PROJECT_ID"
  if [[ "$SKIP_IAM" == false ]]; then
    grant_project_roles "$PROJECT_ID"
  fi
else
  # Org mode — needs a billing project for API enablement checks
  if [[ -z "$BILLING_PROJECT" ]]; then
    echo ""
    echo "Org mode: a billing project is needed to verify API enablement."
    read -r -p "Enter a project ID to use for API checks [or press Enter to skip]: " BILLING_PROJECT
  fi
  echo "Scope: org ($ORG_ID)"
  if [[ -n "$BILLING_PROJECT" ]]; then
    enable_apis "$BILLING_PROJECT"
  else
    warn "Skipping API enablement check — no billing project provided."
  fi
  if [[ "$SKIP_IAM" == false ]]; then
    grant_org_roles "$ORG_ID"
  fi
fi

verify_adc

if [[ "$SKIP_DEPS" == false ]]; then
  install_deps
fi

step "Setup complete"
echo ""
echo "  Activate the virtualenv and run the scanner:"
echo ""
echo "    source $VENV_DIR/bin/activate"
if [[ -n "$PROJECT_ID" ]]; then
  echo "    python krypton.py --project $PROJECT_ID"
else
  echo "    python krypton.py --org $ORG_ID"
fi
echo ""
