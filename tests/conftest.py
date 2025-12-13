"""Shared test fixtures."""

import pytest

from tests.fakes import FakeKubernetes, FakeKubeseal


@pytest.fixture
def fake_kubernetes():
    """Create a FakeKubernetes instance."""
    return FakeKubernetes()


@pytest.fixture
def fake_kubeseal():
    """Create a FakeKubeseal instance."""
    return FakeKubeseal()
