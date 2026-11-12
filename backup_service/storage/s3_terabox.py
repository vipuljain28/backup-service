"""S3-Compatible and TeraBox Storage Provider."""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from backup_service.storage.base import StorageProvider

logger = logging.getLogger("backup_service.s3_terabox")


class S3TeraBoxProvider(StorageProvider):
    """Storage provider for AWS S3, MinIO, Wasabi, and TeraBox S3-compatible APIs."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket_name: str,
        region_name: str = "us-east-1",
        root_prefix: str = "Enterprise_Backups"
    ):
        self.endpoint_url = endpoint_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.bucket_name = bucket_name
        self.region_name = region_name
        self.root_prefix = root_prefix.strip("/")
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        import boto3
        from botocore.config import Config

        session = boto3.session.Session()
        kwargs = {
            "service_name": "s3",
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "region_name": self.region_name,
            "config": Config(s3={"addressing_style": "path"}, signature_version="s3v4")
        }
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url

        self._client = session.client(**kwargs)
        return self._client

    def verify_connection(self) -> bool:
        """Verify bucket access."""
        try:
            client = self._get_client()
            client.head_bucket(Bucket=self.bucket_name)
            logger.info("S3/TeraBox bucket connection verified: %s", self.bucket_name)
            return True
        except Exception as exc:
            logger.error("S3/TeraBox connection test failed: %s", exc)
            return False

    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """S3 is key-value object storage; return clean prefix string."""
        clean_parts = [self.root_prefix] + [
            "".join(c for c in p if c.isalnum() or c in ("-", "_", ".", " "))
            for p in path_parts
        ]
        return "/".join(clean_parts).strip("/")

    def upload_file(self, local_path: Path, destination_folder_id: str, target_filename: str, overwrite: bool = True) -> str:
        """Upload file to S3/TeraBox using multipart upload."""
        local_path = Path(local_path).resolve()
        client = self._get_client()
        s3_key = f"{destination_folder_id}/{target_filename}".strip("/")

        client.upload_file(str(local_path), self.bucket_name, s3_key)
        logger.info("Uploaded %s to S3/TeraBox: s3://%s/%s", target_filename, self.bucket_name, s3_key)
        return s3_key

    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List sub-prefixes using S3 Delimiter='/'."""
        client = self._get_client()
        prefix = parent_folder_id.strip("/") + "/"
        paginator = client.get_paginator("list_objects_v2")
        results = []

        for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                sub_prefix = cp["Prefix"].rstrip("/")
                folder_name = sub_prefix.split("/")[-1]
                results.append({
                    "id": sub_prefix,
                    "name": folder_name,
                    "created_time": None
                })
        return results

    def delete_directory(self, folder_id: str) -> bool:
        """Delete all objects matching prefix."""
        client = self._get_client()
        prefix = folder_id.strip("/") + "/"
        paginator = client.get_paginator("list_objects_v2")

        objects_to_delete = []
        for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
            for obj in page.get("Contents", []):
                objects_to_delete.append({"Key": obj["Key"]})

        if objects_to_delete:
            client.delete_objects(
                Bucket=self.bucket_name,
                Delete={"Objects": objects_to_delete}
            )
        logger.info("Purged S3/TeraBox prefix: %s", prefix)
        return True
