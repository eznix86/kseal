"""FileSystem service for file operations."""

from pathlib import Path
from typing import Protocol


class FileSystem(Protocol):
    """Protocol for filesystem operations."""

    def read_text(self, path: Path) -> str:
        """Read file contents as text."""
        ...

    def write_text(self, path: Path, content: str) -> None:
        """Write text content to file."""
        ...

    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        ...

    def mkdir(self, path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
        """Create directory."""
        ...

    def rglob(self, path: Path, pattern: str) -> list[Path]:
        """Recursively find files matching pattern."""
        ...


class DefaultFileSystem:
    """Default filesystem implementation using pathlib."""

    def read_text(self, path: Path) -> str:
        """Read file contents as text."""
        return path.read_text()

    def write_text(self, path: Path, content: str) -> None:
        """Write text content to file."""
        path.write_text(content)

    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        return path.exists()

    def mkdir(self, path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
        """Create directory."""
        path.mkdir(parents=parents, exist_ok=exist_ok)

    def rglob(self, path: Path, pattern: str) -> list[Path]:
        """Recursively find files matching pattern."""
        return list(path.rglob(pattern))
