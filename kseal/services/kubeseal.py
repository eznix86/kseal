"""Kubeseal service for encrypting secrets."""

import subprocess
from typing import Protocol

from kseal.binary import ensure_kubeseal
from kseal.config import get_controller_name, get_controller_namespace
from kseal.exceptions import KsealError


class Kubeseal(Protocol):
    """Protocol for kubeseal operations."""

    def encrypt(self, secret_yaml: str) -> str:
        """Encrypt a secret YAML string. Returns sealed secret YAML."""
        ...


class DefaultKubeseal:
    """Default Kubeseal implementation that runs the binary."""

    def encrypt(self, secret_yaml: str) -> str:
        """Encrypt a secret using kubeseal binary."""
        kubeseal_path = ensure_kubeseal()
        controller_name = get_controller_name()
        controller_namespace = get_controller_namespace()

        cmd = [
            str(kubeseal_path),
            "--format",
            "yaml",
            "--controller-name",
            controller_name,
            "--controller-namespace",
            controller_namespace,
        ]

        try:
            result = subprocess.run(
                cmd, input=secret_yaml, capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            raise KsealError(f"kubeseal failed: {e.stderr}") from e
        except FileNotFoundError:
            raise KsealError(f"kubeseal binary not found: {kubeseal_path}")

        return result.stdout
