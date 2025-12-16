"""Secret and SealedSecret handling."""

import base64
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from ruamel.yaml.scalarstring import walk_tree

from .exceptions import KsealError
from .services import FileSystem, Kubernetes, Kubeseal
from .services.kubernetes import Secret
from .yaml_utils import YamlDoc, dump_yaml, dump_yaml_docs, parse_yaml, parse_yaml_docs


class SecretRef(BaseModel):
    """Reference to a Kubernetes secret."""

    name: str
    namespace: str = "default"


def load_yaml_file(path: Path, fs: FileSystem) -> YamlDoc:
    """Load a YAML file and return its contents."""
    if not fs.exists(path):
        raise KsealError(f"File not found: {path}")

    doc = parse_yaml(fs.read_text(path))

    if doc is None:
        raise KsealError(f"Empty or invalid YAML file: {path}")

    return doc


def load_yaml_docs(path: Path, fs: FileSystem) -> list[YamlDoc]:
    """Load all YAML documents from a file."""
    if not fs.exists(path):
        raise KsealError(f"File not found: {path}")

    docs = parse_yaml_docs(fs.read_text(path))

    if not docs:
        raise KsealError(f"Empty or invalid YAML file: {path}")

    return docs


def is_sealed_secret(doc: YamlDoc) -> bool:
    """Check if a document is a SealedSecret."""
    return doc.get("kind") == "SealedSecret"


def is_secret(doc: YamlDoc) -> bool:
    """Check if a document is a Secret."""
    return doc.get("kind") == "Secret"


def get_secret_metadata(doc: YamlDoc) -> SecretRef:
    """Extract name and namespace from a SealedSecret or Secret."""
    metadata = doc.get("metadata", {})
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")

    if not name:
        raise KsealError("Secret name not found in metadata")

    return SecretRef(name=name, namespace=namespace)


def format_secret_yaml(secret: YamlDoc) -> str:
    """Format a secret dict as YAML string."""
    return dump_yaml(secret)


def format_secrets_yaml(secrets: list[YamlDoc]) -> str:
    """Format multiple secrets as multi-doc YAML string."""
    for secret in secrets:
        walk_tree(secret)  # Converts multiline strings to literal block style
    return dump_yaml_docs(secrets)


def build_secret_from_cluster_data(cluster_data: Secret) -> YamlDoc:
    """Build a Secret dict from cluster data."""
    metadata: dict[str, Any] = {
        "name": cluster_data.name,
        "namespace": cluster_data.namespace,
    }
    string_data: dict[str, str] = {}

    if cluster_data.labels:
        metadata["labels"] = cluster_data.labels

    if cluster_data.annotations:
        filtered = {
            k: v
            for k, v in cluster_data.annotations.items()
            if not k.startswith("kubectl.kubernetes.io/")
        }
        if filtered:
            metadata["annotations"] = filtered

    for key, value in cluster_data.data.items():
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            string_data[key] = decoded
        except Exception:
            string_data[key] = f"<binary data: {len(value)} bytes>"

    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata,
        "stringData": string_data,
    }


def fetch_secret_from_cluster(
    name: str,
    namespace: str,
    kubernetes: Kubernetes,
) -> YamlDoc:
    """Fetch a Secret from the Kubernetes cluster."""
    cluster_data = kubernetes.get_secret(name, namespace)
    return build_secret_from_cluster_data(cluster_data)


def decrypt_sealed_secret(
    path: Path,
    kubernetes: Kubernetes,
    fs: FileSystem,
) -> list[YamlDoc]:
    """Decrypt all SealedSecrets in a file by fetching from cluster."""
    docs = load_yaml_docs(path, fs)

    sealed_docs = [doc for doc in docs if is_sealed_secret(doc)]
    if not sealed_docs:
        raise KsealError(f"No SealedSecret found in: {path}")

    secrets = []
    for doc in sealed_docs:
        ref = get_secret_metadata(doc)
        secret = fetch_secret_from_cluster(ref.name, ref.namespace, kubernetes)
        secrets.append(secret)

    return secrets


def transform_yaml_docs(
    docs: list[YamlDoc],
    filter: Callable[[YamlDoc], bool],
    transform: Callable[[YamlDoc], YamlDoc],
    error_msg: str,
) -> str:
    """Transform YAML documents that match a filter, preserving others.

    Args:
        docs: List of YAML documents
        filter: Function(doc) -> bool to check if doc should be transformed
        transform: Function(doc) -> dict to transform matching docs
        error_msg: Error message if no docs match filter

    Returns:
        YAML string with transformed docs
    """
    if not docs:
        raise KsealError("Empty or invalid YAML content")

    has_match = any(filter(doc) for doc in docs)
    if not has_match:
        raise KsealError(error_msg)

    result_docs = []
    for doc in docs:
        if filter(doc):
            result_docs.append(transform(doc))
        else:
            result_docs.append(doc)

    return dump_yaml_docs(result_docs)


def encrypt_secret(
    path: Path,
    kubeseal: Kubeseal,
    fs: FileSystem,
) -> str:
    """Encrypt plaintext Secret(s) to SealedSecret using kubeseal.

    Preserves non-Secret documents (ConfigMaps, etc.) in their original positions.
    """
    docs = load_yaml_docs(path, fs)

    def transform(doc: YamlDoc) -> YamlDoc:
        sealed_yaml = kubeseal.encrypt(dump_yaml(doc))
        return parse_yaml(sealed_yaml)

    return transform_yaml_docs(
        docs,
        filter=is_secret,
        transform=transform,
        error_msg=f"No Secret found in: {path}",
    )


def decrypt_secret(
    content: str,
    kubeseal: Kubeseal,
    private_key_paths: list[Path],
) -> str:
    """Decrypt SealedSecret(s) to plaintext Secret using kubeseal.

    Preserves non-SealedSecret documents (ConfigMaps, etc.) in their original positions.
    """
    docs = parse_yaml_docs(content)

    def transform(doc: YamlDoc) -> YamlDoc:
        decrypted_yaml = kubeseal.decrypt(dump_yaml(doc), private_key_paths)
        return parse_yaml(decrypted_yaml)

    return transform_yaml_docs(
        docs,
        filter=is_sealed_secret,
        transform=transform,
        error_msg="No SealedSecret found in content",
    )


def _is_sealed_secret_file(path: Path, fs: FileSystem) -> bool:
    """Check if a file contains a SealedSecret (handles multi-document YAML)."""
    if not fs.exists(path):
        return False

    try:
        docs = parse_yaml_docs(fs.read_text(path))
        return any(is_sealed_secret(doc) for doc in docs)
    except Exception:
        return False


def find_sealed_secrets(root: Path, fs: FileSystem) -> list[Path]:
    """Find all SealedSecret files recursively from root."""
    sealed_secrets = []

    for yaml_file in fs.rglob(root, "*.yaml"):
        if _is_sealed_secret_file(yaml_file, fs):
            sealed_secrets.append(yaml_file)

    for yml_file in fs.rglob(root, "*.yml"):
        if _is_sealed_secret_file(yml_file, fs):
            sealed_secrets.append(yml_file)

    return sorted(sealed_secrets)
