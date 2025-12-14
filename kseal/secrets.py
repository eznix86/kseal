"""Secret and SealedSecret handling."""

import base64
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import walk_tree

from .exceptions import KsealError
from .services import FileSystem, Kubernetes, Kubeseal

yaml = YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False
yaml.width = 4096  # Prevent line wrapping


def load_yaml_file(path: Path, fs: FileSystem) -> dict:
    """Load a YAML file and return its contents."""
    if not fs.exists(path):
        raise KsealError(f"File not found: {path}")

    content = fs.read_text(path)
    doc = yaml.load(StringIO(content))

    if doc is None:
        raise KsealError(f"Empty or invalid YAML file: {path}")

    return doc


def load_yaml_docs(path: Path, fs: FileSystem) -> list[dict]:
    """Load all YAML documents from a file."""
    if not fs.exists(path):
        raise KsealError(f"File not found: {path}")

    content = fs.read_text(path)
    docs = list(yaml.load_all(StringIO(content)))

    if not docs or all(doc is None for doc in docs):
        raise KsealError(f"Empty or invalid YAML file: {path}")

    return [doc for doc in docs if doc is not None]


def is_sealed_secret(doc: dict) -> bool:
    """Check if a document is a SealedSecret."""
    return doc.get("kind") == "SealedSecret"


def is_secret(doc: dict) -> bool:
    """Check if a document is a Secret."""
    return doc.get("kind") == "Secret"


def get_secret_metadata(doc: dict) -> tuple[str, str]:
    """Extract name and namespace from a SealedSecret or Secret."""
    metadata = doc.get("metadata", {})
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")

    if not name:
        raise KsealError("Secret name not found in metadata")

    return name, namespace


def format_secret_yaml(secret: dict) -> str:
    """Format a secret dict as YAML string."""
    stream = StringIO()
    yaml.dump(secret, stream)
    return stream.getvalue()


def format_secrets_yaml(secrets: list[dict]) -> str:
    """Format multiple secrets as multi-doc YAML string."""
    for secret in secrets:
        walk_tree(secret)  # Converts multiline strings to literal block style
    stream = StringIO()
    yaml.dump_all(secrets, stream)
    return stream.getvalue()


def build_secret_from_cluster_data(cluster_data: dict) -> dict:
    """Build a Secret dict from cluster data."""
    metadata: dict = {
        "name": cluster_data["name"],
        "namespace": cluster_data["namespace"],
    }
    string_data: dict = {}

    if cluster_data.get("labels"):
        metadata["labels"] = cluster_data["labels"]

    if cluster_data.get("annotations"):
        filtered = {
            k: v
            for k, v in cluster_data["annotations"].items()
            if not k.startswith("kubectl.kubernetes.io/")
        }
        if filtered:
            metadata["annotations"] = filtered

    for key, value in cluster_data.get("data", {}).items():
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
) -> dict:
    """Fetch a Secret from the Kubernetes cluster."""
    cluster_data = kubernetes.get_secret(name, namespace)
    return build_secret_from_cluster_data(cluster_data)


def decrypt_sealed_secret(
    path: Path,
    kubernetes: Kubernetes,
    fs: FileSystem,
) -> list[dict]:
    """Decrypt all SealedSecrets in a file by fetching from cluster."""
    docs = load_yaml_docs(path, fs)

    sealed_docs = [doc for doc in docs if is_sealed_secret(doc)]
    if not sealed_docs:
        raise KsealError(f"No SealedSecret found in: {path}")

    secrets = []
    for doc in sealed_docs:
        name, namespace = get_secret_metadata(doc)
        secret = fetch_secret_from_cluster(name, namespace, kubernetes)
        secrets.append(secret)

    return secrets


def encrypt_secret(
    path: Path,
    kubeseal: Kubeseal,
    fs: FileSystem,
) -> str:
    """Encrypt plaintext Secret(s) to SealedSecret using kubeseal.

    Preserves non-Secret documents (ConfigMaps, etc.) in their original positions.
    """
    docs = load_yaml_docs(path, fs)

    has_secret = any(is_secret(doc) for doc in docs)
    if not has_secret:
        raise KsealError(f"No Secret found in: {path}")

    result_docs = []
    for doc in docs:
        if is_secret(doc):
            # Encrypt this Secret
            stream = StringIO()
            yaml.dump(doc, stream)
            secret_yaml = stream.getvalue()
            sealed_yaml = kubeseal.encrypt(secret_yaml)
            sealed_doc = yaml.load(StringIO(sealed_yaml))
            result_docs.append(sealed_doc)
        else:
            # Preserve non-Secret documents as-is
            result_docs.append(doc)

    output_stream = StringIO()
    yaml.dump_all(result_docs, output_stream)
    return output_stream.getvalue()


def _is_sealed_secret_file(path: Path, fs: FileSystem) -> bool:
    """Check if a file contains a SealedSecret (handles multi-document YAML)."""
    if not fs.exists(path):
        return False

    try:
        content = fs.read_text(path)
        docs = yaml.load_all(StringIO(content))
        for doc in docs:
            if doc and is_sealed_secret(doc):
                return True
    except Exception:
        return False

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
