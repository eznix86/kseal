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
                "secret.yaml": """\
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
            output="""\
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
                "config.yaml": """\
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

        assert "not a Secret" in str(exc_info.value)

    def test_raises_on_kubeseal_error(self):
        fs = FakeFileSystem(
            files={
                "secret.yaml": """\
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
                "secret.yaml": """\
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
                "secret.yaml": """\
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
