"""Kubeseal binary management - download and version handling."""

from __future__ import annotations

import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TransferSpeedColumn,
)
from rich.status import Status

from .config import get_version as get_config_version
from .github import get_latest_version
from .settings import add_downloaded_version, get_default_version

DOWNLOAD_URL_TEMPLATE = (
    "https://github.com/bitnami-labs/sealed-secrets/releases/download/"
    "v{version}/kubeseal-{version}-{os}-{arch}.tar.gz"
)

# Re-export for backwards compatibility
__all__ = ["get_latest_version"]


def get_default_binary_dir() -> Path:
    """Get the default directory for kubeseal binaries."""
    return Path.home() / ".local" / "share" / "kseal"


def get_default_binary_path(version: str) -> Path:
    """Get the default path for a specific kubeseal version."""
    return get_default_binary_dir() / f"kubeseal-{version}"


def get_binary_version(binary_path: Path) -> str | None:
    """Get the version of an installed kubeseal binary.

    Returns version string (e.g., "0.25.0") or None if unable to determine.
    """
    try:
        result = subprocess.run(
            [str(binary_path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Output format: "kubeseal version: 0.25.0"
        if result.returncode == 0:
            output = result.stdout.strip()
            if "version:" in output:
                return output.split("version:")[-1].strip()
    except Exception:
        pass
    return None


def find_kubeseal_in_path() -> Path | None:
    """Check if kubeseal is available in system PATH."""
    kubeseal_path = shutil.which("kubeseal")
    if kubeseal_path:
        return Path(kubeseal_path)
    return None


def detect_os() -> str:
    """Detect the operating system."""
    system = platform.system().lower()
    if system == "darwin":
        return "darwin"
    if system == "linux":
        return "linux"
    raise RuntimeError(f"Unsupported operating system: {system}")


def detect_arch() -> str:
    """Detect the CPU architecture."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    raise RuntimeError(f"Unsupported architecture: {machine}")


def get_version() -> str:
    """Get the kubeseal version to use.

    Priority:
    1. Project config version (from .kseal-config.yaml)
    2. Global default version (from settings.yaml)
    3. Highest downloaded version
    4. Fetch latest from GitHub (fallback)
    """
    # 1. Check project config
    config_version = get_config_version()
    if config_version:
        return config_version

    # 2 & 3. Check global default or highest downloaded
    default = get_default_version()
    if default:
        return default

    # 4. Fallback to latest from GitHub
    return get_latest_version()


def download_kubeseal(version: str, target_path: Path) -> None:
    """Download and extract kubeseal binary."""
    console = Console()
    os_name = detect_os()
    arch = detect_arch()

    url = DOWNLOAD_URL_TEMPLATE.format(version=version, os=os_name, arch=arch)

    target_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball_path = Path(tmpdir) / "kubeseal.tar.gz"

        with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response:
            _ = response.raise_for_status()
            total_size = int(response.headers.get("content-length", 0))

            with Progress(
                TextColumn("[bold blue]Downloading kubeseal v{version}...".format(version=version)),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("download", total=total_size)

                with open(tarball_path, "wb") as f:
                    for chunk in response.iter_bytes():
                        _ = f.write(chunk)
                        _ = progress.update(task, advance=len(chunk))

        with Status("[bold blue]Extracting...[/]", console=console):
            with tarfile.open(tarball_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == "kubeseal" or member.name.endswith("/kubeseal"):
                        member.name = "kubeseal"
                        tar.extract(member, tmpdir, filter="data")
                        break
                else:
                    raise RuntimeError("kubeseal binary not found in tarball")

            extracted_binary = Path(tmpdir) / "kubeseal"
            _ = extracted_binary.rename(target_path)

    target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Register the downloaded version in global settings
    add_downloaded_version(version)

    console.print(f"[bold green]✓[/] Installed kubeseal v{version} to {target_path}")


def ensure_kubeseal() -> Path:
    """Ensure kubeseal binary is available with correct version.

    Search order:
    1. Versioned binary at default location (~/.local/share/kseal/kubeseal-X.Y.Z)
    2. System PATH (only if version matches)
    3. Download if not found or version mismatch
    """
    target_version = get_version()
    default_path = get_default_binary_path(target_version)

    # 1. Check if versioned binary already exists
    if default_path.exists():
        installed_version = get_binary_version(default_path)
        if installed_version == target_version:
            return default_path
        # Version mismatch in filename - corrupted, redownload

    # 2. Check system PATH (only if version matches)
    system_kubeseal = find_kubeseal_in_path()
    if system_kubeseal:
        system_version = get_binary_version(system_kubeseal)
        if system_version == target_version:
            return system_kubeseal

    # 3. Download the correct version
    download_kubeseal(target_version, default_path)
    return default_path
