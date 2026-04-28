from __future__ import annotations

import asyncio

from ...application.ports import PresignedUpload, StoragePort


class S3StorageAdapter(StoragePort):
    def __init__(self, s3_client: object, bucket: str) -> None:
        self._s3 = s3_client
        self._bucket = bucket

    async def create_presigned_upload(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUpload:
        fields = {"Content-Type": content_type}
        conditions = [{"Content-Type": content_type}]

        response = await asyncio.to_thread(
            self._s3.generate_presigned_post,
            self._bucket,
            storage_key,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=expires_in_seconds,
        )
        return PresignedUpload(
            url=response["url"],
            fields=response["fields"],
            expires_in_seconds=expires_in_seconds,
        )

    async def create_presigned_download(
        self,
        storage_key: str,
        expires_in_seconds: int = 900,
    ) -> str:
        return await asyncio.to_thread(
            self._s3.generate_presigned_url,
            "get_object",
            Params={"Bucket": self._bucket, "Key": storage_key},
            ExpiresIn=expires_in_seconds,
        )

    async def delete_object(self, storage_key: str) -> None:
        await asyncio.to_thread(
            self._s3.delete_object,
            Bucket=self._bucket,
            Key=storage_key,
        )
