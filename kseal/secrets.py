"""Secret and SealedSecret handling."""

import base64
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML

from .exceptions import KsealError
from .services import FileSystem, Kubernetes, Kubeseal
from .services.filesystem import DefaultFileSystem

yaml = YAML()
yaml.preserve_quotes = True

_default_fs = DefaultFileSystem()


def load_yaml_file(path: Path, fs: FileSystem = _default_fs) -> dict:
    """Load a YAML file and return its contents."""
    if not fs.exists(path):
        raise KsealError(f"File not found: {path}")

    content = fs.read_text(path)
    doc = yaml.load(StringIO(content))

    if doc is None:
        raise KsealError(f"Empty or invalid YAML file: {path}")

    return doc


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


def build_secret_from_cluster_data(cluster_data: dict) -> dict:
    """Build a Secret dict from cluster data."""
    result = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": cluster_data["name"],
            "namespace": cluster_data["namespace"],
        },
        "stringData": {},
    }

    if cluster_data.get("labels"):
        result["metadata"]["labels"] = cluster_data["labels"]

    if cluster_data.get("annotations"):
        filtered = {
            k: v
            for k, v in cluster_data["annotations"].items()
            if not k.startswith("kubectl.kubernetes.io/")
        }
        if filtered:
            result["metadata"]["annotations"] = filtered

    for key, value in cluster_data.get("data", {}).items():
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            result["stringData"][key] = decoded
        except Exception:
            result["stringData"][key] = f"<binary data: {len(value)} bytes>"

    return result


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
    fs: FileSystem = _default_fs,
) -> dict:
    """Decrypt a SealedSecret by fetching the actual Secret from the cluster."""
    doc = load_yaml_file(path, fs)

    if not is_sealed_secret(doc):
        raise KsealError(f"File is not a SealedSecret: {path}")

    name, namespace = get_secret_metadata(doc)
    return fetch_secret_from_cluster(name, namespace, kubernetes)


def encrypt_secret(
    path: Path,
    kubeseal: Kubeseal,
    fs: FileSystem = _default_fs,
) -> str:
    """Encrypt a plaintext Secret to SealedSecret using kubeseal."""
    doc = load_yaml_file(path, fs)

    if not is_secret(doc):
        raise KsealError(f"File is not a Secret: {path}")

    input_yaml = fs.read_text(path)

    return kubeseal.encrypt(input_yaml)


def _is_sealed_secret_file(path: Path, fs: FileSystem = _default_fs) -> bool:
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


def find_sealed_secrets(
    root: Path = Path("."), fs: FileSystem = _default_fs
) -> list[Path]:
    """Find all SealedSecret files recursively from root."""
    sealed_secrets = []

    for yaml_file in fs.rglob(root, "*.yaml"):
        if _is_sealed_secret_file(yaml_file, fs):
            sealed_secrets.append(yaml_file)

    for yml_file in fs.rglob(root, "*.yml"):
        if _is_sealed_secret_file(yml_file, fs):
            sealed_secrets.append(yml_file)

    return sorted(sealed_secrets)
