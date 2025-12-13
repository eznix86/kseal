"""Kubeseal binary management - download and version handling."""

import platform
import shutil
import stat
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

from .config import get_kubeseal_path
from .config import get_version as get_config_version

GITHUB_API_URL = "https://api.github.com/repos/bitnami-labs/sealed-secrets/releases/latest"
DOWNLOAD_URL_TEMPLATE = (
    "https://github.com/bitnami-labs/sealed-secrets/releases/download/"
    "v{version}/kubeseal-{version}-{os}-{arch}.tar.gz"
)


def get_default_binary_path() -> Path:
    """Get the default path for the kubeseal binary."""
    return Path.home() / ".local" / "share" / "kseal" / "kubeseal"


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


def get_latest_version() -> str:
    """Fetch the latest kubeseal version from GitHub API."""
    response = httpx.get(GITHUB_API_URL, follow_redirects=True, timeout=30)
    response.raise_for_status()
    data = response.json()
    tag = data["tag_name"]
    return tag.lstrip("v")


def get_version() -> str:
    """Get the kubeseal version to use."""
    version = get_config_version()
    if version and version.lower() != "latest":
        return version
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
            response.raise_for_status()
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
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))

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
            extracted_binary.rename(target_path)

    target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    console.print(f"[bold green]✓[/] Installed kubeseal v{version} to {target_path}")


def ensure_kubeseal() -> Path:
    """Ensure kubeseal binary is available, downloading if necessary.

    Search order:
    1. Config file or KSEAL_KUBESEAL_PATH environment variable
    2. System PATH (globally installed kubeseal)
    3. Default location (~/.local/share/kseal/kubeseal)
    4. Download if not found anywhere
    """
    configured_path = get_kubeseal_path()
    default_path_str = str(get_default_binary_path())

    if configured_path != default_path_str:
        path = Path(configured_path)
        if path.exists():
            return path
        raise RuntimeError(f"Configured kubeseal path not found: {configured_path}")

    system_kubeseal = find_kubeseal_in_path()
    if system_kubeseal:
        return system_kubeseal

    default_path = get_default_binary_path()
    if default_path.exists():
        return default_path

    version = get_version()
    download_kubeseal(version, default_path)

    return default_path
