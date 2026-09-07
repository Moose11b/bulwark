"""
Evidence file storage for the standalone app.

Files (screenshots, PCAPs, logs) are written to a local directory, partitioned
per organization, named by a random id (never by a client-supplied name, so
there is no path-traversal surface). Content is encrypted at rest with the same
key as the rest of the app when one is configured. The DB holds only metadata
(hash, size, content type, and the encrypted original filename).

The interface is deliberately small so a future object-store backend (S3, etc.)
can drop in behind it.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import db  # reference db._ENC dynamically (survives test reloads)

_DEFAULT_DIR = str(Path(__file__).resolve().parent.parent / "evidence_store")

MAX_EVIDENCE_BYTES = int(os.environ.get("SIEGE_MAX_EVIDENCE_BYTES", str(25 * 1024 * 1024)))


def _base_dir() -> str:
    return os.environ.get("SIEGE_EVIDENCE_DIR", _DEFAULT_DIR)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_for(org_id: str, evidence_id: str) -> Path:
    # org_id and evidence_id are server-generated UUIDs — safe as path segments.
    d = Path(_base_dir()) / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d / evidence_id


def save(org_id: str, evidence_id: str, data: bytes) -> None:
    path = _path_for(org_id, evidence_id)
    blob = db._ENC.encrypt_bytes(data)
    # Write via a temp file then atomically replace; restrict permissions.
    tmp = path.with_suffix(".tmp")
    with open(tmp, "wb") as fh:
        fh.write(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load(org_id: str, evidence_id: str) -> bytes:
    path = _path_for(org_id, evidence_id)
    with open(path, "rb") as fh:
        return db._ENC.decrypt_bytes(fh.read())


def exists(org_id: str, evidence_id: str) -> bool:
    return _path_for(org_id, evidence_id).is_file()


def remove(org_id: str, evidence_id: str) -> None:
    path = _path_for(org_id, evidence_id)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
