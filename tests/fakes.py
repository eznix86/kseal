"""Fake implementations of external services for testing."""

import fnmatch
from pathlib import Path

from kseal.exceptions import KsealError


class FakeFileSystem:
    """In-memory filesystem for testing."""

    def __init__(self, files: dict[str, str] | None = None):
        self.files: dict[str, str] = files or {}
        self.directories: set[str] = set()

    def read_text(self, path: Path) -> str:
        """Read file contents as text."""
        key = str(path)
        if key not in self.files:
            raise FileNotFoundError(f"No such file: {path}")
        return self.files[key]

    def write_text(self, path: Path, content: str) -> None:
        """Write text content to file."""
        self.files[str(path)] = content

    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        key = str(path)
        return key in self.files or key in self.directories

    def mkdir(self, path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
        """Create directory."""
        self.directories.add(str(path))

    def rglob(self, path: Path, pattern: str) -> list[Path]:
        """Recursively find files matching pattern."""
        result = []
        root = str(path)
        for filepath in self.files:
            # Check if file is under root
            if root == "." or filepath.startswith(root + "/") or filepath == root:
                # Check if filename matches pattern
                if fnmatch.fnmatch(Path(filepath).name, pattern):
                    result.append(Path(filepath))
        return sorted(result)


class FakeKubernetes:
    """Fake Kubernetes service for testing."""

    def __init__(
        self,
        secrets: dict[tuple[str, str], dict] | None = None,
        cluster_secrets: list[dict] | None = None,
    ):
        self.secrets = secrets or {}
        self.cluster_secrets = cluster_secrets or []
        self.calls: list[tuple[str, str]] = []
        self.list_calls: int = 0

    def get_secret(self, name: str, namespace: str) -> dict:
        self.calls.append((name, namespace))
        key = (name, namespace)
        if key not in self.secrets:
            raise KsealError(f"Secret '{name}' not found in namespace '{namespace}'")
        return self.secrets[key]

    def list_sealed_secrets(self) -> list[dict]:
        self.list_calls += 1
        return self.cluster_secrets


class FakeKubeseal:
    """Fake Kubeseal service for testing."""

    def __init__(self, output: str = "kind: SealedSecret\n", error: str | None = None):
        self.output = output
        self.error = error
        self.calls: list[str] = []

    def encrypt(self, secret_yaml: str) -> str:
        self.calls.append(secret_yaml)
        if self.error:
            raise KsealError(self.error)
        return self.output
