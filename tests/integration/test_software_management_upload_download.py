from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from software_management.bootstrap import SMSBootstrapConfig, build_sms_module


@contextmanager
def writable_temp_dir() -> Generator[Path, None, None]:
    root = Path(
        os.environ.get(
            "SMS_TEST_TMP_ROOT",
            r"C:\Users\HomePC\AppData\Local\Temp\codex_py_temp",
        )
    )
    root.mkdir(parents=True, exist_ok=True)
    tmp_path = root / f"sms_test_{uuid.uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    try:
        yield tmp_path
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


@contextmanager
def sms_test_client(
    *,
    max_upload_size_bytes: int,
    upload_rate_limit: int = 30,
    upload_rate_window_seconds: int = 60,
    download_rate_limit: int = 120,
    download_rate_window_seconds: int = 60,
) -> Generator[TestClient, None, None]:
    with writable_temp_dir() as base_path:
        database_path = base_path / "sms.db"
        storage_path = base_path / "storage"

        async def current_actor_dependency(
            x_actor_user: str = Header(..., alias="X-Actor-User"),
            x_actor_role: str = Header("USER", alias="X-Actor-Role"),
        ) -> dict:
            return {"user_id": x_actor_user, "role": x_actor_role}

        app = FastAPI()
        sms_module = build_sms_module(
            config=SMSBootstrapConfig(
                database_url=f"sqlite:///{database_path}",
                storage_root=storage_path,
                upload_chunk_size=4,
                upload_max_size_bytes=max_upload_size_bytes,
                upload_rate_limit=upload_rate_limit,
                upload_rate_window_seconds=upload_rate_window_seconds,
                download_rate_limit=download_rate_limit,
                download_rate_window_seconds=download_rate_window_seconds,
            ),
            current_actor_dependency=current_actor_dependency,
        )
        # In integration tests we bootstrap a temporary SQLite DB directly.
        asyncio.run(sms_module.database.create_schema())
        asyncio.run(sms_module.initialize())
        app.include_router(sms_module.router)
        try:
            with TestClient(app) as client:
                yield client
        finally:
            asyncio.run(sms_module.close())


def test_unauthorized_download_does_not_increment_count() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        owner_headers = {"X-Actor-User": "owner-1"}
        upload_response = client.post(
            "/api/v1/software-management/upload",
            headers=owner_headers,
            data={
                "software_name": "private-package",
                "software_description": "private artifact",
                "version": "1.0.0",
                "is_public": "false",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", b"private-content", "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        software_id = upload_response.json()["software_id"]

        denied_response = client.get(
            f"/api/v1/software-management/{software_id}/versions/1.0.0/download",
            headers={"X-Actor-User": "attacker-1"},
        )
        assert denied_response.status_code == 403

        versions_response = client.get(
            f"/api/v1/software-management/{software_id}/versions",
            headers=owner_headers,
        )
        assert versions_response.status_code == 200
        versions = versions_response.json()
        assert len(versions) == 1
        assert versions[0]["download_count"] == 0


def test_successful_download_increments_count_and_streams() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        owner_headers = {"X-Actor-User": "owner-2"}
        payload = b"public-download-content"
        upload_response = client.post(
            "/api/v1/software-management/upload",
            headers=owner_headers,
            data={
                "software_name": "public-package",
                "software_description": "public artifact",
                "version": "2.0.0",
                "is_public": "true",
                "publish_now": "true",
            },
            files={"file": ("artifact.bin", payload, "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        software_id = upload_response.json()["software_id"]

        download_response = client.get(
            f"/api/v1/software-management/{software_id}/versions/2.0.0/download",
            headers={"X-Actor-User": "consumer-1"},
        )
        assert download_response.status_code == 200
        assert download_response.content == payload
        assert download_response.headers["Content-Length"] == str(len(payload))

        versions_response = client.get(
            f"/api/v1/software-management/{software_id}/versions",
            headers=owner_headers,
        )
        assert versions_response.status_code == 200
        versions = versions_response.json()
        assert len(versions) == 1
        assert versions[0]["download_count"] == 1


def test_upload_rejected_when_exceeding_max_size() -> None:
    with sms_test_client(max_upload_size_bytes=8) as client:
        response = client.post(
            "/api/v1/software-management/upload",
            headers={"X-Actor-User": "owner-3"},
            data={
                "software_name": "size-capped",
                "software_description": "",
                "version": "3.0.0",
                "is_public": "true",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", b"123456789", "application/octet-stream")},
        )
        assert response.status_code == 422
        assert "maximum allowed size" in response.json()["detail"]


def test_upload_rate_limit_returns_429() -> None:
    with sms_test_client(
        max_upload_size_bytes=1024,
        upload_rate_limit=1,
        upload_rate_window_seconds=60,
    ) as client:
        headers = {"X-Actor-User": "owner-4"}
        payload = {
            "software_name": "rate-limited-upload",
            "software_description": "",
            "version": "1.0.0",
            "is_public": "true",
            "publish_now": "false",
        }
        first = client.post(
            "/api/v1/software-management/upload",
            headers=headers,
            data=payload,
            files={"file": ("artifact.bin", b"abc", "application/octet-stream")},
        )
        assert first.status_code == 201

        second = client.post(
            "/api/v1/software-management/upload",
            headers=headers,
            data={**payload, "version": "1.0.1"},
            files={"file": ("artifact.bin", b"def", "application/octet-stream")},
        )
        assert second.status_code == 429


def test_download_rate_limit_returns_429() -> None:
    with sms_test_client(
        max_upload_size_bytes=1024,
        download_rate_limit=1,
        download_rate_window_seconds=60,
    ) as client:
        owner_headers = {"X-Actor-User": "owner-5"}
        upload_response = client.post(
            "/api/v1/software-management/upload",
            headers=owner_headers,
            data={
                "software_name": "rate-limited-download",
                "software_description": "",
                "version": "1.0.0",
                "is_public": "true",
                "publish_now": "true",
            },
            files={"file": ("artifact.bin", b"download-me", "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        software_id = upload_response.json()["software_id"]
        path = f"/api/v1/software-management/{software_id}/versions/1.0.0/download"
        consumer_headers = {"X-Actor-User": "consumer-2"}

        first = client.get(path, headers=consumer_headers)
        assert first.status_code == 200

        second = client.get(path, headers=consumer_headers)
        assert second.status_code == 429


def test_upload_idempotency_returns_same_response() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        headers = {"X-Actor-User": "owner-6", "Idempotency-Key": "upload-key-1"}
        payload = b"repeatable"
        response1 = client.post(
            "/api/v1/software-management/upload",
            headers=headers,
            data={
                "software_name": "idempotent-upload",
                "software_description": "first",
                "version": "1.2.3",
                "is_public": "true",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", payload, "application/octet-stream")},
        )
        assert response1.status_code == 201
        response2 = client.post(
            "/api/v1/software-management/upload",
            headers=headers,
            data={
                "software_name": "idempotent-upload",
                "software_description": "first",
                "version": "1.2.3",
                "is_public": "true",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", payload, "application/octet-stream")},
        )
        assert response2.status_code == 201
        assert response2.json() == response1.json()

        software_id = response1.json()["software_id"]
        versions_response = client.get(
            f"/api/v1/software-management/{software_id}/versions",
            headers={"X-Actor-User": "owner-6"},
        )
        assert versions_response.status_code == 200
        assert len(versions_response.json()) == 1


def test_publish_idempotency_returns_same_response() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        owner_headers = {"X-Actor-User": "owner-7"}
        upload_response = client.post(
            "/api/v1/software-management/upload",
            headers=owner_headers,
            data={
                "software_name": "idempotent-publish",
                "software_description": "pending",
                "version": "0.9.0",
                "is_public": "true",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", b"publish-me", "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        software_id = upload_response.json()["software_id"]

        publish_headers = {"X-Actor-User": "owner-7", "Idempotency-Key": "publish-key-1"}
        response1 = client.post(
            f"/api/v1/software-management/{software_id}/versions/0.9.0/publish",
            headers=publish_headers,
        )
        assert response1.status_code == 200
        response2 = client.post(
            f"/api/v1/software-management/{software_id}/versions/0.9.0/publish",
            headers=publish_headers,
        )
        assert response2.status_code == 200
        assert response2.json() == response1.json()


def test_upload_rejects_hash_mismatch() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        payload = b"hash-check"
        correct_hash = hashlib.sha256(payload).hexdigest()
        response = client.post(
            "/api/v1/software-management/upload",
            headers={"X-Actor-User": "owner-8", "X-Artifact-Hash": correct_hash[:-1] + "0"},
            data={
                "software_name": "hash-check",
                "software_description": "",
                "version": "4.0.0",
                "is_public": "true",
                "publish_now": "false",
            },
            files={"file": ("artifact.bin", payload, "application/octet-stream")},
        )
        assert response.status_code == 422
        assert "hash mismatch" in response.json()["detail"]


def test_deprecate_and_revoke_version_flow() -> None:
    with sms_test_client(max_upload_size_bytes=1024) as client:
        owner_headers = {"X-Actor-User": "owner-9"}
        upload_response = client.post(
            "/api/v1/software-management/upload",
            headers=owner_headers,
            data={
                "software_name": "lifecycle-ui",
                "software_description": "package",
                "version": "1.0.0",
                "is_public": "true",
                "publish_now": "true",
            },
            files={"file": ("artifact.bin", b"data", "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        software_id = upload_response.json()["software_id"]

        deprecate = client.post(
            f"/api/v1/software-management/{software_id}/versions/1.0.0/deprecate",
            headers=owner_headers,
        )
        assert deprecate.status_code == 200
        assert deprecate.json()["version"] == "1.0.0"

        revoke = client.post(
            f"/api/v1/software-management/{software_id}/versions/1.0.0/revoke",
            headers=owner_headers,
        )
        assert revoke.status_code == 200
        assert revoke.json()["version"] == "1.0.0"
