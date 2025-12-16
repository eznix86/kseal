"""Kubeseal service for encrypting and decrypting secrets."""

import base64
import subprocess
from pathlib import Path
from typing import Any, Protocol

from kseal.binary import ensure_kubeseal
from kseal.config import get_controller_name, get_controller_namespace
from kseal.exceptions import KsealError
from kseal.yaml_utils import YamlDoc, dump_yaml_docs, parse_yaml_docs


def _clean_secret_yaml(raw_yaml: str) -> str:
    """Clean up kubeseal decrypt output.

    - Convert base64 `data` to plain `stringData`
    - Remove `ownerReferences`
    - Reorder keys to standard order
    """
    docs = parse_yaml_docs(raw_yaml)
    result_docs: list[YamlDoc] = []

    for doc in docs:
        if doc.get("kind") != "Secret":
            result_docs.append(doc)
            continue

        # Convert base64 data to stringData
        data: dict[str, Any] = doc.get("data", {})
        string_data: dict[str, str] = {}
        for key, value in data.items():
            try:
                string_data[key] = base64.b64decode(value).decode("utf-8")
            except Exception:
                string_data[key] = value

        # Clean up metadata
        metadata: dict[str, Any] = doc.get("metadata", {})
        _ = metadata.pop("ownerReferences", None)
        _ = metadata.pop("creationTimestamp", None)

        # Build clean secret with proper key order
        clean_secret: YamlDoc = {
            "apiVersion": doc.get("apiVersion", "v1"),
            "kind": "Secret",
            "metadata": metadata,
            "stringData": string_data,
        }

        # Preserve type if present
        if "type" in doc:
            clean_secret["type"] = doc["type"]

        result_docs.append(clean_secret)

    return dump_yaml_docs(result_docs)


def _run_kubeseal(cmd: list[str], input_yaml: str, operation: str) -> str:
    """Run kubeseal command and handle errors.

    Args:
        cmd: Command arguments
        input_yaml: YAML content to pass to stdin
        operation: Operation name for error messages (e.g., "encrypt", "decrypt")

    Returns:
        stdout from kubeseal
    """
    try:
        result = subprocess.run(cmd, input=input_yaml, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else ""
        raise KsealError(f"kubeseal {operation} failed: {stderr}") from e
    except FileNotFoundError:
        raise KsealError(f"kubeseal binary not found: {cmd[0]}")


class Kubeseal(Protocol):
    """Protocol for kubeseal operations."""

    def encrypt(self, secret_yaml: str) -> str:
        """Encrypt a secret YAML string. Returns sealed secret YAML."""
        ...

    def decrypt(self, sealed_yaml: str, private_key_paths: list[Path]) -> str:
        """Decrypt a sealed secret YAML using private keys. Returns secret YAML."""
        ...


class DefaultKubeseal:
    """Default Kubeseal implementation that runs the binary."""

    def encrypt(self, secret_yaml: str) -> str:
        """Encrypt a secret using kubeseal binary."""
        kubeseal_path = ensure_kubeseal()

        cmd = [
            str(kubeseal_path),
            "--format",
            "yaml",
            "--controller-name",
            get_controller_name(),
            "--controller-namespace",
            get_controller_namespace(),
        ]

        return _run_kubeseal(cmd, secret_yaml, "encrypt")

    def decrypt(self, sealed_yaml: str, private_key_paths: list[Path]) -> str:
        """Decrypt a sealed secret using kubeseal --recovery-unseal.

        Args:
            sealed_yaml: The SealedSecret YAML content
            private_key_paths: List of paths to private key files

        Returns:
            Decrypted Secret YAML
        """
        if not private_key_paths:
            raise KsealError("No private keys provided for decryption")

        kubeseal_path = ensure_kubeseal()
        keys_arg = ",".join(str(p) for p in private_key_paths)

        cmd = [
            str(kubeseal_path),
            "--recovery-unseal",
            "--recovery-private-key",
            keys_arg,
            "-o",
            "yaml",
        ]

        return _clean_secret_yaml(_run_kubeseal(cmd, sealed_yaml, "decrypt"))
