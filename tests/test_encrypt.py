"""Tests for the encrypt feature - encrypting secrets to SealedSecrets."""

from pathlib import Path

import pytest

from kseal.cli import encrypt_to_sealed
from kseal.exceptions import KsealError
from tests.fakes import FakeFileSystem, FakeKubeseal


class TestEncryptToSealed:
    def test_encrypts_secret_file(self):
        fs = FakeFileSystem(
            files={
                "secret.yaml": """
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: production
stringData:
  password: super-secret
"""
            }
        )

        kubeseal = FakeKubeseal(
            output="""
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: my-secret
  namespace: production
spec:
  encryptedData:
    password: AgBy8hCi...
"""
        )

        result = encrypt_to_sealed(Path("secret.yaml"), kubeseal, fs)

        assert "SealedSecret" in result
        assert "encryptedData" in result
        assert len(kubeseal.calls) == 1
        assert "kind: Secret" in kubeseal.calls[0]

    def test_raises_when_not_a_secret(self):
        fs = FakeFileSystem(
            files={
                "config.yaml": """
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value
"""
            }
        )

        kubeseal = FakeKubeseal()

        with pytest.raises(KsealError) as exc_info:
            encrypt_to_sealed(Path("config.yaml"), kubeseal, fs)

        assert "No Secret found" in str(exc_info.value)

    def test_raises_on_kubeseal_error(self):
        fs = FakeFileSystem(
            files={
                "secret.yaml": """
apiVersion: v1
kind: Secret
metadata:
  name: test
stringData:
  key: value
"""
            }
        )

        kubeseal = FakeKubeseal(error="kubeseal: error: cannot fetch certificate")

        with pytest.raises(KsealError) as exc_info:
            encrypt_to_sealed(Path("secret.yaml"), kubeseal, fs)

        assert "cannot fetch certificate" in str(exc_info.value)

    def test_preserves_secret_content_for_kubeseal(self):
        fs = FakeFileSystem(
            files={
                "secret.yaml": """
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
  namespace: production
  labels:
    app: myapp
stringData:
  username: admin
  password: hunter2
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\n")

        encrypt_to_sealed(Path("secret.yaml"), kubeseal, fs)

        sent_yaml = kubeseal.calls[0]
        assert "username: admin" in sent_yaml
        assert "password: hunter2" in sent_yaml
        assert "namespace: production" in sent_yaml

    def test_handles_empty_stringdata(self):
        fs = FakeFileSystem(
            files={
                "secret.yaml": """
apiVersion: v1
kind: Secret
metadata:
  name: empty
stringData: {}
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\n")

        result = encrypt_to_sealed(Path("secret.yaml"), kubeseal, fs)

        assert "SealedSecret" in result

    def test_preserves_deployment_before_secret(self):
        """Deployment at start, Secret at end."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
---
kind: Secret
metadata:
  name: secret1
stringData:
  password: secret
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: secret1\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Deployment" in result
        assert "kind: SealedSecret" in result
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 1

    def test_preserves_service_after_secret(self):
        """Secret at start, Service at end."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Secret
metadata:
  name: secret1
stringData:
  password: secret
---
kind: Service
metadata:
  name: my-service
spec:
  ports:
    - port: 80
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: secret1\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Service" in result
        assert "kind: SealedSecret" in result
        assert "kind: Secret" not in result

    def test_preserves_pod_between_secrets(self):
        """Secret, Pod, Secret - Pod sandwiched between secrets."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Secret
metadata:
  name: secret1
stringData:
  key: value1
---
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: app
      image: nginx
---
kind: Secret
metadata:
  name: secret2
stringData:
  key: value2
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Pod" in result
        assert result.count("kind: SealedSecret") == 2
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 2

    def test_preserves_mixed_resources_with_secrets_sandwiched(self):
        """Deployment, Secret, Service, Secret, ConfigMap, Pod - secrets sandwiched."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Deployment
metadata:
  name: my-deployment
---
kind: Secret
metadata:
  name: db-creds
stringData:
  password: dbpass
---
kind: Service
metadata:
  name: my-service
---
kind: Secret
metadata:
  name: api-key
stringData:
  key: apikey123
---
kind: ConfigMap
metadata:
  name: app-config
---
kind: Pod
metadata:
  name: debug-pod
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Deployment" in result
        assert "kind: Service" in result
        assert "kind: ConfigMap" in result
        assert "kind: Pod" in result
        assert result.count("kind: SealedSecret") == 2
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 2

    def test_preserves_ingress_and_namespace_around_secret(self):
        """Namespace, Secret, Ingress - different resource types."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Namespace
metadata:
  name: my-namespace
---
kind: Secret
metadata:
  name: tls-cert
stringData:
  cert: certdata
---
kind: Ingress
metadata:
  name: my-ingress
spec:
  rules:
    - host: example.com
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Namespace" in result
        assert "kind: Ingress" in result
        assert "kind: SealedSecret" in result
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 1

    def test_preserves_three_secrets_with_resources_between(self):
        """Secret, Deployment, Secret, Service, Secret - multiple sandwiches."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Secret
metadata:
  name: secret1
stringData:
  key: value1
---
kind: Deployment
metadata:
  name: app
---
kind: Secret
metadata:
  name: secret2
stringData:
  key: value2
---
kind: Service
metadata:
  name: svc
---
kind: Secret
metadata:
  name: secret3
stringData:
  key: value3
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Deployment" in result
        assert "kind: Service" in result
        assert result.count("kind: SealedSecret") == 3
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 3

    def test_preserves_existing_sealed_secret_with_new_secret(self):
        """SealedSecret and Secret together - encrypt Secret, preserve SealedSecret."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: SealedSecret
metadata:
  name: already-sealed
spec:
  encryptedData:
    password: existingencrypted
---
kind: Secret
metadata:
  name: new-secret
stringData:
  key: newvalue
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: new-secret\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        # Existing SealedSecret should be preserved
        assert "name: already-sealed" in result
        # New Secret should be encrypted
        assert "name: new-secret" in result
        assert result.count("kind: SealedSecret") == 2
        assert "kind: Secret" not in result
        # Only the Secret was sent to kubeseal, not the existing SealedSecret
        assert len(kubeseal.calls) == 1

    def test_preserves_sealed_secret_between_secrets(self):
        """Secret, SealedSecret, Secret - SealedSecret sandwiched."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Secret
metadata:
  name: secret1
stringData:
  key: value1
---
kind: SealedSecret
metadata:
  name: existing-sealed
spec:
  encryptedData:
    data: encrypted
---
kind: Secret
metadata:
  name: secret2
stringData:
  key: value2
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "name: existing-sealed" in result
        assert result.count("kind: SealedSecret") == 3
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 2

    def test_mixed_sealed_secrets_secrets_and_other_resources(self):
        """Complex mix: Deployment, SealedSecret, Secret, ConfigMap, SealedSecret, Secret."""
        fs = FakeFileSystem(
            files={
                "multi.yaml": """
---
kind: Deployment
metadata:
  name: app
---
kind: SealedSecret
metadata:
  name: sealed1
spec:
  encryptedData:
    key: enc1
---
kind: Secret
metadata:
  name: secret1
stringData:
  key: value1
---
kind: ConfigMap
metadata:
  name: config
---
kind: SealedSecret
metadata:
  name: sealed2
spec:
  encryptedData:
    key: enc2
---
kind: Secret
metadata:
  name: secret2
stringData:
  key: value2
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: new-sealed\n")

        result = encrypt_to_sealed(Path("multi.yaml"), kubeseal, fs)

        assert "kind: Deployment" in result
        assert "kind: ConfigMap" in result
        assert "name: sealed1" in result
        assert "name: sealed2" in result
        assert result.count("kind: SealedSecret") == 4
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 2

    def test_raises_when_only_sealed_secrets(self):
        """Only SealedSecrets, no Secret to encrypt - should error."""
        fs = FakeFileSystem(
            files={
                "sealed-only.yaml": """
---
kind: SealedSecret
metadata:
  name: sealed1
spec:
  encryptedData:
    key: enc1
---
kind: SealedSecret
metadata:
  name: sealed2
spec:
  encryptedData:
    key: enc2
"""
            }
        )

        kubeseal = FakeKubeseal()

        with pytest.raises(KsealError) as exc_info:
            encrypt_to_sealed(Path("sealed-only.yaml"), kubeseal, fs)

        assert "No Secret found" in str(exc_info.value)

    def test_raises_when_single_sealed_secret(self):
        """Single SealedSecret only - should error."""
        fs = FakeFileSystem(
            files={
                "sealed.yaml": """
kind: SealedSecret
metadata:
  name: already-sealed
spec:
  encryptedData:
    key: encrypted
"""
            }
        )

        kubeseal = FakeKubeseal()

        with pytest.raises(KsealError) as exc_info:
            encrypt_to_sealed(Path("sealed.yaml"), kubeseal, fs)

        assert "No Secret found" in str(exc_info.value)

    def test_encrypts_multiple_secrets_only(self):
        """Multiple Secrets only, no other resources."""
        fs = FakeFileSystem(
            files={
                "secrets.yaml": """
---
kind: Secret
metadata:
  name: secret1
stringData:
  key: value1
---
kind: Secret
metadata:
  name: secret2
stringData:
  key: value2
---
kind: Secret
metadata:
  name: secret3
stringData:
  key: value3
"""
            }
        )

        kubeseal = FakeKubeseal(output="kind: SealedSecret\nmetadata:\n  name: sealed\n")

        result = encrypt_to_sealed(Path("secrets.yaml"), kubeseal, fs)

        assert result.count("kind: SealedSecret") == 3
        assert "kind: Secret" not in result
        assert len(kubeseal.calls) == 3
