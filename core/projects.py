"""
Project enumeration.
Supports single project or full org traversal via Cloud Resource Manager.
Individual project failures are caught and logged — never abort the full run.
"""

import logging
from typing import List, Optional

from core.auth import build_service

logger = logging.getLogger(__name__)


def get_projects(
    project_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> List[str]:
    if project_id and org_id:
        raise ValueError("Provide either --project or --org, not both.")
    if not project_id and not org_id:
        raise ValueError("Provide either --project or --org.")
    if project_id:
        return [project_id]
    return _search_org_projects(org_id)


def _search_org_projects(org_id: str) -> List[str]:
    """
    Find all ACTIVE projects in an organisation.

    Strategy:
      1. Try projects.search() with just the parent filter (no state filter —
         some API versions ignore combined filters silently).
      2. Filter ACTIVE state client-side from the results.

    Requires resourcemanager.projects.list at org level.
    """
    service = build_service("cloudresourcemanager", "v3")
    project_ids: List[str] = []
    page_token: Optional[str] = None

    logger.info(f"Searching for active projects in org {org_id} ...")

    # Use parent filter only — filter state client-side
    # Combined query strings behave inconsistently across API versions
    query = f"parent:organizations/{org_id}"

    while True:
        kwargs = {"query": query}
        if page_token:
            kwargs["pageToken"] = page_token

        try:
            response = service.projects().search(**kwargs).execute()
            logger.debug(f"search() raw response keys: {list(response.keys())}")
            logger.debug(f"projects in page: {len(response.get('projects', []))}")
        except Exception as exc:
            logger.error(f"projects.search() failed: {exc}")
            break

        for project in response.get("projects", []):
            pid   = project.get("projectId", "")
            state = project.get("state", "")
            logger.debug(f"  project: {pid}  state: {state}")
            if pid and state == "ACTIVE":
                project_ids.append(pid)

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    # If search returned nothing at all, fall back to listing folders recursively
    if not project_ids:
        logger.info("search() returned no results — trying folder-aware list() fallback ...")
        project_ids = _list_projects_via_folders(service, org_id)

    logger.info(f"Found {len(project_ids)} active project(s).")
    return project_ids


def _list_projects_via_folders(service, org_id: str) -> List[str]:
    """
    Fallback: walk the org hierarchy manually.
    Lists projects directly under org root, then recursively under each folder.
    Handles orgs where search() returns empty due to permission scope.
    """
    project_ids: List[str] = []

    # Projects directly under org root
    project_ids.extend(_list_projects_under_parent(service, f"organizations/{org_id}"))

    # Folders directly under org, then recurse
    folders = _list_folders_under_parent(service, f"organizations/{org_id}")
    while folders:
        folder = folders.pop()
        project_ids.extend(_list_projects_under_parent(service, folder))
        folders.extend(_list_folders_under_parent(service, folder))

    return project_ids


def _list_projects_under_parent(service, parent: str) -> List[str]:
    pids = []
    page_token = None
    while True:
        kwargs = {"parent": parent}
        if page_token:
            kwargs["pageToken"] = page_token
        try:
            resp = service.projects().list(**kwargs).execute()
        except Exception as exc:
            logger.warning(f"projects.list(parent={parent}) failed: {exc}")
            break
        for p in resp.get("projects", []):
            pid   = p.get("projectId", "")
            state = p.get("state", "")
            logger.debug(f"  [list] project: {pid}  state: {state}  parent: {parent}")
            if pid and state == "ACTIVE":
                pids.append(pid)
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return pids


def _list_folders_under_parent(service, parent: str) -> List[str]:
    folder_names = []
    page_token = None
    while True:
        kwargs = {"parent": parent}
        if page_token:
            kwargs["pageToken"] = page_token
        try:
            resp = service.folders().list(**kwargs).execute()
        except Exception as exc:
            logger.warning(f"folders.list(parent={parent}) failed: {exc}")
            break
        for f in resp.get("folders", []):
            name  = f.get("name", "")
            state = f.get("state", "")
            if name and state == "ACTIVE":
                folder_names.append(name)
                logger.debug(f"  [list] folder: {name}")
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return folder_names
