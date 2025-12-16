"""Helper functions for offline decryption of SealedSecrets."""

import re
from pathlib import Path

from .exceptions import KsealError
from .services import FileSystem


def get_private_key_paths(
    keys_path: Path,
    regex: str,
    fs: FileSystem,
) -> list[Path]:
    """Get paths to private key files, filtered by regex pattern.

    Args:
        keys_path: Directory containing private key files
        regex: Regex pattern to filter key file names
        fs: FileSystem service

    Returns:
        List of paths to matching key files
    """
    if not fs.exists(keys_path):
        raise KsealError(f"Keys directory not found: {keys_path}")

    pattern = re.compile(regex)
    key_paths = []

    for key_file in fs.rglob(keys_path, "*.key"):
        if pattern.search(key_file.name):
            key_paths.append(key_file)

    if not key_paths:
        raise KsealError(f"No keys found in {keys_path} matching pattern '{regex}'")

    return key_paths
