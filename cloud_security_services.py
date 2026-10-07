"""External security integrations used by the Cloud Rdx Flask application."""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import tempfile
from pathlib import Path
from urllib.parse import quote


class MalwareScannerUnavailable(RuntimeError):
    """Raised when the configured ClamAV scanner cannot return a valid result."""


def scan_with_clamav(path: Path) -> tuple[str, str | None]:
    host = os.getenv("CLAMD_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("CLAMD_PORT", "3310"))
        timeout = float(os.getenv("CLAMD_TIMEOUT_SECONDS", "15"))
    except ValueError as error:
        raise MalwareScannerUnavailable("ClamAV settings are invalid") from error
    if not 1 <= port <= 65535 or not 1 <= timeout <= 120:
        raise MalwareScannerUnavailable("ClamAV settings are outside supported limits")

    try:
        with socket.create_connection((host, port), timeout=timeout) as scanner:
            scanner.settimeout(timeout)
            scanner.sendall(b"zINSTREAM\0")
            with path.open("rb") as source:
                while chunk := source.read(64 * 1024):
                    scanner.sendall(struct.pack("!I", len(chunk)))
                    scanner.sendall(chunk)
            scanner.sendall(struct.pack("!I", 0))
            response = bytearray()
            while b"\0" not in response and b"\n" not in response:
                chunk = scanner.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except (OSError, TimeoutError) as error:
        raise MalwareScannerUnavailable("ClamAV did not return a scan result") from error

    result = bytes(response).split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()
    if result.endswith(": OK"):
        return "clean", None
    if result.endswith(" FOUND"):
        return "infected", result.rsplit(": ", 1)[-1][:-6]
    raise MalwareScannerUnavailable("ClamAV returned an inconclusive scan result")


def _azure_container(container_name: str):
    account_url = os.getenv("CLOUD_RDX_AZURE_ACCOUNT_URL", "").strip()
    if not account_url.startswith("https://"):
        raise RuntimeError("CLOUD_RDX_AZURE_ACCOUNT_URL must be an HTTPS Azure Blob endpoint")
    if not container_name or not container_name.replace("-", "").isalnum():
        raise RuntimeError("The configured Azure Blob container name is invalid")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient
    except ImportError as error:
        raise RuntimeError(
            "Azure storage support is unavailable; install requirements.txt"
        ) from error

    credential = DefaultAzureCredential()
    try:
        service = BlobServiceClient(account_url=account_url, credential=credential)
        container = service.get_container_client(container_name)
        yield container
    finally:
        credential.close()


class azure_container:
    """Context manager that authenticates using the Azure SDK credential chain."""

    def __init__(self, container_name: str):
        self.container_name = container_name
        self._generator = None

    def __enter__(self):
        self._generator = _azure_container(self.container_name)
        return next(self._generator)

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            next(self._generator)
        except StopIteration:
            return False


def sync_local_files(shared_folder: Path, container_name: str) -> dict[str, int]:
    users_root = (shared_folder / "users").resolve()
    if not users_root.is_dir():
        raise RuntimeError("The local users storage directory is unavailable")

    counts = {"uploaded": 0, "unchanged": 0, "unstable": 0}
    with azure_container(container_name) as container:
        container.get_container_properties()
        for source in users_root.rglob("*"):
            if source.is_symlink() or not source.is_file():
                continue
            resolved = source.resolve()
            try:
                relative = resolved.relative_to(users_root)
            except ValueError:
                continue
            initial = source.stat()
            with tempfile.TemporaryFile(mode="w+b") as snapshot:
                digest = hashlib.sha256()
                with source.open("rb") as original:
                    while chunk := original.read(1024 * 1024):
                        digest.update(chunk)
                        snapshot.write(chunk)
                final = source.stat()
                if (
                    initial.st_size != final.st_size
                    or initial.st_mtime_ns != final.st_mtime_ns
                ):
                    counts["unstable"] += 1
                    continue

                file_hash = digest.hexdigest()
                blob_name = (
                    f"sync/users/{quote(relative.as_posix(), safe='/-._')}/"
                    f"{file_hash}"
                )
                blob = container.get_blob_client(blob_name)
                if blob.exists():
                    counts["unchanged"] += 1
                    continue

                snapshot.seek(0)
                blob.upload_blob(
                    snapshot,
                    overwrite=False,
                    metadata={
                        "sha256": file_hash,
                        "source_mtime": str(int(final.st_mtime)),
                    },
                )
                counts["uploaded"] += 1
    return counts


def verify_immutable_container(container) -> int:
    properties = container.get_container_properties()
    policy = getattr(properties, "immutability_policy", None)
    mode = getattr(policy, "policy_mode", None)
    retention_days = getattr(
        policy, "immutability_period_since_creation_in_days", None
    )
    if str(mode).casefold() not in {"locked", "lockedimmutable"}:
        raise RuntimeError(
            "The backup container must have a locked Azure immutability policy"
        )
    if isinstance(retention_days, bool) or not isinstance(retention_days, int):
        raise RuntimeError("The backup container has no valid immutable retention period")
    required_days = int(os.getenv("CLOUD_RDX_BACKUP_RETENTION_DAYS", "90"))
    if required_days < 1 or retention_days < required_days:
        raise RuntimeError(
            f"The locked backup retention must be at least {required_days} days"
        )
    return retention_days


def upload_immutable_backup(
    archive_path: Path, container_name: str, blob_name: str, digest: str
) -> int:
    with azure_container(container_name) as container:
        retention_days = verify_immutable_container(container)
        blob = container.get_blob_client(blob_name)
        with archive_path.open("rb") as backup:
            blob.upload_blob(
                backup,
                overwrite=False,
                metadata={"sha256": digest, "retention_days": str(retention_days)},
            )
    return retention_days

