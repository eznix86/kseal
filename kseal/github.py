"""GitHub API utilities for fetching kubeseal releases."""

from typing import Any

import httpx

GITHUB_API_URL = "https://api.github.com/repos/bitnami-labs/sealed-secrets/releases/latest"


def get_latest_version() -> str:
    """Fetch the latest kubeseal version from GitHub API."""
    response = httpx.get(GITHUB_API_URL, follow_redirects=True, timeout=30)
    _ = response.raise_for_status()
    data: dict[str, Any] = response.json()
    tag: str = data["tag_name"]
    return tag.lstrip("v")
