"""Tests for multiline YAML string formatting using literal block style."""

import base64

from kseal.secrets import build_secret_from_cluster_data, format_secrets_yaml
from kseal.services.kubernetes import Secret
from kseal.services.kubeseal import _clean_secret_yaml


class TestBuildSecretFromClusterData:
    """Tests for build_secret_from_cluster_data multiline handling."""

    def test_multiline_value_uses_literal_block_style(self):
        """Multiline values should use literal block style (|) in output."""
        multiline_config = "server:\n  host: localhost\n  port: 8080\n"
        secret = Secret(
            name="config-secret",
            namespace="default",
            data={"config.yml": base64.b64encode(multiline_config.encode()).decode()},
        )

        result = build_secret_from_cluster_data(secret)
        yaml_output = format_secrets_yaml([result])

        # Should use literal block style, not escaped newlines
        assert "config.yml: |" in yaml_output or "config.yml: |-" in yaml_output
        assert "\\n" not in yaml_output
        assert "server:" in yaml_output
        assert "host: localhost" in yaml_output

    def test_single_line_value_stays_inline(self):
        """Single line values should stay inline, not use block style."""
        secret = Secret(
            name="simple-secret",
            namespace="default",
            data={"password": base64.b64encode(b"mysecret").decode()},
        )

        result = build_secret_from_cluster_data(secret)
        yaml_output = format_secrets_yaml([result])

        # Single line should be inline
        assert "password: mysecret" in yaml_output
        assert "password: |" not in yaml_output

    def test_mixed_single_and_multiline_values(self):
        """Mixed single and multiline values should be handled correctly."""
        multiline_config = "key1: value1\nkey2: value2\n"
        secret = Secret(
            name="mixed-secret",
            namespace="default",
            data={
                "config.yml": base64.b64encode(multiline_config.encode()).decode(),
                "api_key": base64.b64encode(b"secret123").decode(),
            },
        )

        result = build_secret_from_cluster_data(secret)
        yaml_output = format_secrets_yaml([result])

        # Multiline should use block style
        assert "config.yml: |" in yaml_output or "config.yml: |-" in yaml_output
        # Single line should be inline
        assert "api_key: secret123" in yaml_output

    def test_multiline_with_empty_lines(self):
        """Multiline with empty lines should preserve them."""
        config_with_empty = "section1:\n  key: value\n\nsection2:\n  key: value\n"
        secret = Secret(
            name="config-secret",
            namespace="default",
            data={"config.yml": base64.b64encode(config_with_empty.encode()).decode()},
        )

        result = build_secret_from_cluster_data(secret)
        yaml_output = format_secrets_yaml([result])

        assert "\\n" not in yaml_output
        assert "section1:" in yaml_output
        assert "section2:" in yaml_output

    def test_multiline_json_content(self):
        """JSON content with newlines should use literal block style."""
        json_config = '{\n  "key": "value",\n  "number": 123\n}\n'
        secret = Secret(
            name="json-secret",
            namespace="default",
            data={"config.json": base64.b64encode(json_config.encode()).decode()},
        )

        result = build_secret_from_cluster_data(secret)
        yaml_output = format_secrets_yaml([result])

        assert "config.json: |" in yaml_output or "config.json: |-" in yaml_output
        assert '"key": "value"' in yaml_output


class TestCleanSecretYaml:
    """Tests for _clean_secret_yaml multiline handling."""

    def test_multiline_base64_decoded_uses_block_style(self):
        """Multiline content from base64 should use literal block style."""
        multiline_content = "line1\nline2\nline3\n"
        encoded = base64.b64encode(multiline_content.encode()).decode()
        raw_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: default
data:
  config: {encoded}
"""

        result = _clean_secret_yaml(raw_yaml)

        assert "config: |" in result or "config: |-" in result
        assert "\\n" not in result
        assert "line1" in result
        assert "line2" in result

    def test_single_line_base64_stays_inline(self):
        """Single line content should stay inline."""
        encoded = base64.b64encode(b"simple-value").decode()
        raw_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: default
data:
  password: {encoded}
"""

        result = _clean_secret_yaml(raw_yaml)

        assert "password: simple-value" in result
        assert "password: |" not in result

    def test_preserves_non_secret_documents(self):
        """Non-Secret documents should pass through unchanged."""
        raw_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
"""

        result = _clean_secret_yaml(raw_yaml)

        assert "kind: ConfigMap" in result
        assert "key: value" in result

    def test_handles_multiple_secrets_with_multiline(self):
        """Multiple secrets with multiline content should all use block style."""
        config1 = base64.b64encode(b"key1: val1\nkey2: val2\n").decode()
        config2 = base64.b64encode(b"setting: true\noption: false\n").decode()
        raw_yaml = f"""apiVersion: v1
kind: Secret
metadata:
  name: secret1
  namespace: default
data:
  config: {config1}
---
apiVersion: v1
kind: Secret
metadata:
  name: secret2
  namespace: default
data:
  settings: {config2}
"""

        result = _clean_secret_yaml(raw_yaml)

        # Both should use block style
        assert result.count(": |") >= 2 or result.count(": |-") >= 2
        assert "\\n" not in result


class TestFormatSecretsYaml:
    """Tests for format_secrets_yaml multiline handling."""

    def test_walk_tree_converts_existing_multiline(self):
        """walk_tree should convert existing multiline strings."""
        secrets = [
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "test", "namespace": "default"},
                "stringData": {"config": "line1\nline2\n"},
            }
        ]

        result = format_secrets_yaml(secrets)

        # Should use literal block style after walk_tree
        assert "\\n" not in result
        assert "line1" in result
        assert "line2" in result
