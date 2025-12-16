"""Kubernetes service for fetching secrets from the cluster."""

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel

from kseal.exceptions import KsealError


class Secret(BaseModel):
    """Kubernetes secret data."""

    name: str
    namespace: str
    data: dict[str, str] = {}
    labels: dict[str, str] | None = None
    annotations: dict[str, str] | None = None


class SealingKey(BaseModel):
    """Sealed-secrets private key."""

    name: str
    tls_key: bytes
    created_at: datetime


class Kubernetes(Protocol):
    """Protocol for Kubernetes operations."""

    def get_secret(self, name: str, namespace: str) -> Secret:
        """Fetch a secret from the cluster."""
        ...

    def list_sealed_secrets(self) -> list[Secret]:
        """List all secrets managed by sealed-secrets controller."""
        ...

    def get_sealing_keys(self, namespace: str = "sealed-secrets") -> list[SealingKey]:
        """Fetch sealed-secrets private keys from cluster."""
        ...


def _k8s_secret_to_model(secret) -> Secret:
    """Convert a Kubernetes V1Secret to our Secret model."""
    metadata = secret.metadata
    if metadata is None:
        raise KsealError("Secret has no metadata")

    return Secret(
        name=metadata.name,
        namespace=metadata.namespace,
        data=dict(secret.data) if secret.data else {},
        labels=dict(metadata.labels) if metadata.labels else None,
        annotations=dict(metadata.annotations) if metadata.annotations else None,
    )


class DefaultKubernetes:
    """Default Kubernetes implementation that connects to a cluster."""

    def get_secret(self, name: str, namespace: str) -> Secret:
        """Fetch a secret from the cluster."""
        from kubernetes import client
        from kubernetes import config as k8s_config

        try:
            k8s_config.load_kube_config()
        except Exception as e:
            raise KsealError(f"Failed to load kubeconfig: {e}") from e

        v1 = client.CoreV1Api()

        try:
            secret = v1.read_namespaced_secret(name, namespace)
        except client.ApiException as e:
            if e.status == 404:
                raise KsealError(f"Secret '{name}' not found in namespace '{namespace}'") from e
            raise KsealError(f"Failed to fetch secret: {e}") from e

        return _k8s_secret_to_model(secret)

    def list_sealed_secrets(self) -> list[Secret]:
        """List all secrets managed by sealed-secrets controller.

        Finds secrets that have an owner reference to a SealedSecret.
        """
        from kubernetes import client
        from kubernetes import config as k8s_config

        try:
            k8s_config.load_kube_config()
        except Exception as e:
            raise KsealError(f"Failed to load kubeconfig: {e}") from e

        v1 = client.CoreV1Api()

        try:
            secrets = v1.list_secret_for_all_namespaces()
        except client.ApiException as e:
            raise KsealError(f"Failed to list secrets: {e}") from e

        result = []
        for secret in secrets.items:
            metadata = secret.metadata
            if metadata is None:
                continue
            owner_refs = metadata.owner_references or []
            is_sealed = any(ref.kind == "SealedSecret" for ref in owner_refs)
            if is_sealed:
                result.append(_k8s_secret_to_model(secret))

        return result

    def get_sealing_keys(self, namespace: str = "sealed-secrets") -> list[SealingKey]:
        """Fetch sealed-secrets private keys from cluster."""
        import base64

        from kubernetes import client
        from kubernetes import config as k8s_config

        try:
            k8s_config.load_kube_config()
        except Exception as e:
            raise KsealError(f"Failed to load kubeconfig: {e}") from e

        v1 = client.CoreV1Api()

        try:
            secrets = v1.list_namespaced_secret(
                namespace,
                label_selector="sealedsecrets.bitnami.com/sealed-secrets-key",
            )
        except client.ApiException as e:
            raise KsealError(f"Failed to list sealing keys: {e}") from e

        result = []
        for secret in secrets.items:
            metadata = secret.metadata
            if metadata is None:
                continue
            tls_key_b64 = secret.data.get("tls.key") if secret.data else None
            if not tls_key_b64:
                continue

            result.append(
                SealingKey(
                    name=metadata.name,
                    tls_key=base64.b64decode(tls_key_b64),
                    created_at=metadata.creation_timestamp,
                )
            )

        return result
