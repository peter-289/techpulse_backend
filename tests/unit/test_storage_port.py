"""Guards the storage port consolidation.

``app/infrastructure/storage/local_storage.py`` used to define its own copies of
the ``Storage`` protocol, the signer protocol and the whole
``StorageError`` hierarchy, duplicating the ones in
``app/modules/software_management/domain/ports/storage.py`` and
``app/modules/software_management/domain/ports/download_signer.py``.

That duplication was invisible until a service caught the domain exceptions
while the adapter raised the infrastructure ones: the ``except`` clauses simply
never fired, and a missing artifact would surface as a 500 from somewhere other
than the error handler. These tests pin the two names to the same class, so the
duplication cannot come back.
"""

from __future__ import annotations

import pytest

from app.exceptions import handlers
from app.infrastructure.storage import local_storage
from app.infrastructure.storage.local_storage import (
    HmacDownloadUrlSigner,
    LocalStorage,
)
from app.modules.software_management.domain.ports import download_signer as domain_signer
from app.modules.software_management.domain.ports import storage as domain_storage


@pytest.mark.parametrize(
    "name",
    [
        "StorageError",
        "StorageUnavailableError",
        "StorageWriteError",
        "StorageReadError",
        "StorageFileNotFoundError",
        "StorageSecurityError",
    ],
)
def test_adapter_raises_the_domain_exception_classes(name: str) -> None:
    assert getattr(local_storage, name) is getattr(domain_storage, name)


def test_storage_protocol_has_a_single_definition() -> None:
    assert local_storage.Storage is domain_storage.Storage


def test_signer_contract_has_a_single_definition() -> None:
    assert local_storage.DownloadSigner is domain_signer.DownloadSigner
    assert local_storage.SignedDownloadUrl is domain_signer.SignedDownloadUrl


def test_error_handlers_map_the_classes_the_adapter_raises() -> None:
    """The HTTP mapping must be keyed to the same classes the adapter raises.

    ``handlers.py`` translating storage failures to status codes is only
    correct while it holds the same class objects the adapter raises. Had
    ``handlers`` kept importing the adapter's private duplicates, this identity
    would fail -- which is exactly the split that let a service's ``except
    StorageFileNotFoundError`` clause go dead.
    """
    for name in (
        "StorageError",
        "StorageUnavailableError",
        "StorageWriteError",
        "StorageReadError",
        "StorageFileNotFoundError",
        "StorageSecurityError",
    ):
        assert getattr(handlers, name) is getattr(domain_storage, name), (
            f"handlers.{name} is not the class the adapter raises"
        )


@pytest.mark.parametrize("adapter", [LocalStorage, HmacDownloadUrlSigner])
def test_adapters_satisfy_their_ports(adapter: type) -> None:
    port = (
        domain_storage.Storage
        if adapter is LocalStorage
        else domain_signer.DownloadSigner
    )
    assert all(hasattr(adapter, member) for member in port.__protocol_attrs__)


def test_port_exposes_only_the_documented_members() -> None:
    """Guards against a port quietly growing to mirror the whole adapter.

    The point of a per-context port is that it lists what the context needs. A
    port that accumulates every attribute of the concrete adapter stops
    restricting anything, and the R2 boundary it supports stops meaning
    anything.
    """
    assert set(domain_storage.Storage.__protocol_attrs__) == {
        "save",
        "open",
        "delete",
        "exists",
    }
    assert set(domain_signer.DownloadSigner.__protocol_attrs__) == {
        "create_url",
        "verify_token",
    }
