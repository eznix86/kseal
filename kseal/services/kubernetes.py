"""Kubernetes service for fetching secrets from the cluster."""

from typing import Protocol

from kseal.exceptions import KsealError


class Kubernetes(Protocol):
    """Protocol for Kubernetes operations."""

    def get_secret(self, name: str, namespace: str) -> dict:
        """Fetch a secret from the cluster.

        Returns dict with keys: name, namespace, data, labels, annotations.
        """
        ...

    def list_sealed_secrets(self) -> list[dict]:
        """List all secrets managed by sealed-secrets controller.

        Returns list of dicts with keys: name, namespace, data, labels, annotations.
        """
        ...


class DefaultKubernetes:
    """Default Kubernetes implementation that connects to a cluster."""

    def get_secret(self, name: str, namespace: str) -> dict:
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

        return {
            "name": secret.metadata.name,
            "namespace": secret.metadata.namespace,
            "data": dict(secret.data) if secret.data else {},
            "labels": dict(secret.metadata.labels) if secret.metadata.labels else None,
            "annotations": dict(secret.metadata.annotations)
            if secret.metadata.annotations
            else None,
        }

    def list_sealed_secrets(self) -> list[dict]:
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
            owner_refs = secret.metadata.owner_references or []
            is_sealed = any(ref.kind == "SealedSecret" for ref in owner_refs)
            if not is_sealed:
                continue

            result.append({
                "name": secret.metadata.name,
                "namespace": secret.metadata.namespace,
                "data": dict(secret.data) if secret.data else {},
                "labels": dict(secret.metadata.labels) if secret.metadata.labels else None,
                "annotations": dict(secret.metadata.annotations)
                if secret.metadata.annotations
                else None,
            })

        return result
