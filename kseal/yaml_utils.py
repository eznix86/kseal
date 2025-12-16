"""YAML utilities for consistent YAML handling across kseal."""

from io import StringIO
from typing import Any

from ruamel.yaml import YAML

# Type alias for YAML documents
YamlDoc = dict[str, Any]

# Shared YAML instance with consistent settings
yaml = YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False
yaml.width = 4096  # Prevent line wrapping


def parse_yaml(content: str) -> YamlDoc:
    """Parse YAML string to dict."""
    result: YamlDoc = yaml.load(StringIO(content))
    return result


def parse_yaml_docs(content: str) -> list[YamlDoc]:
    """Parse multi-doc YAML string to list of dicts (filters None docs)."""
    docs: list[Any] = list(yaml.load_all(StringIO(content)))
    return [doc for doc in docs if doc is not None]


def dump_yaml(doc: YamlDoc) -> str:
    """Dump dict to YAML string."""
    stream = StringIO()
    yaml.dump(doc, stream)
    return stream.getvalue()


def dump_yaml_docs(docs: list[YamlDoc]) -> str:
    """Dump list of dicts to multi-doc YAML string."""
    stream = StringIO()
    yaml.dump_all(docs, stream)
    return stream.getvalue()
