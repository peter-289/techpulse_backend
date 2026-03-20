from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterable, AsyncIterator
from uuid import uuid4

import aiofiles
import aiofiles.os as aioos
import aiofiles.ospath as aiospath

from software_management.application.dtos import StoredObject
from software_management.application.errors import NotFoundError, ValidationError
from software_management.application.interfaces import StorageService


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class LocalStorageConfig:
    root: Path
    max_upload_size_bytes: int | None = None


class LocalAsyncStorageService(StorageService):
    def __init__(self, config: LocalStorageConfig) -> None:
        self._root = config.root
        self._max_upload_size_bytes = config.max_upload_size_bytes
        self._root.mkdir(parents=True, exist_ok=True)

    async def store_stream(
        self,
        stream: AsyncIterable[bytes],
        *,
        file_name: str,
        content_type: str,
    ) -> StoredObject:
        object_id = uuid4().hex
        storage_key = f"artifacts/{object_id[:2]}/{object_id}"
        file_path = self._resolve(storage_key)
        await asyncio.to_thread(file_path.parent.mkdir, parents=True, exist_ok=True)

        total_bytes = 0
        hasher = hashlib.sha256()
        try:
            async with aiofiles.open(file_path, "wb") as handle:
                async for chunk in stream:
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if (
                        self._max_upload_size_bytes is not None
                        and total_bytes > self._max_upload_size_bytes
                    ):
                        raise ValidationError("upload exceeds maximum allowed size")
                    hasher.update(chunk)
                    await handle.write(chunk)
        except Exception:
            await self.delete(storage_key)
            raise
        if total_bytes <= 0:
            await self.delete(storage_key)
            raise ValidationError("empty file uploads are not allowed")

        return StoredObject(
            storage_key=storage_key,
            file_hash=hasher.hexdigest(),
            size_bytes=total_bytes,
            file_name=file_name,
            content_type=content_type or "application/octet-stream",
            created_at=_utc_now(),
        )

    async def open_stream(
        self,
        storage_key: str,
        *,
        chunk_size: int,
        start: int = 0,
        end: int | None = None,
    ) -> AsyncIterator[bytes]:
        path = self._resolve(storage_key)
        if not await aiospath.exists(path):
            raise NotFoundError("artifact not found in storage")

        async def _stream() -> AsyncIterator[bytes]:
            async with aiofiles.open(path, "rb") as handle:
                if start > 0:
                    await handle.seek(start)
                remaining = None if end is None else max(0, end - start + 1)
                while True:
                    read_size = chunk_size if remaining is None else min(chunk_size, remaining)
                    if read_size <= 0:
                        break
                    chunk = await handle.read(read_size)
                    if not chunk:
                        break
                    if remaining is not None:
                        remaining -= len(chunk)
                    yield chunk

        return _stream()

    async def delete(self, storage_key: str) -> None:
        path = self._resolve(storage_key)
        try:
            await aioos.remove(path)
        except FileNotFoundError:
            return
        except Exception:
            return

    def _resolve(self, storage_key: str) -> Path:
        candidate = (self._root / storage_key).resolve()
        root = self._root.resolve()
        if not str(candidate).startswith(str(root)):
            raise ValidationError("invalid storage key")
        return candidate
