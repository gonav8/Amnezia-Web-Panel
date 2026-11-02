"""Authenticated encryption for panel-held SSH and authenticator secrets.

The 256-bit key must be provisioned outside the panel state volume and mounted
read-only at SSH_CREDENTIALS_KEY_FILE (default: /run/secrets/ssh-credentials-key).
It is deliberately never generated or persisted by this module.
"""
from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = "aesgcm-v1"
ENVELOPE_FIELD = "__prvtpro_secret_envelope__"
DEFAULT_KEY_FILE = "/run/secrets/ssh-credentials-key"
NONCE_BYTES = 12
KEY_BYTES = 32


class SecretStorageError(RuntimeError):
    """Safe-to-report secret-storage configuration or integrity failure."""


def key_file_path() -> Path:
    return Path(os.environ.get("SSH_CREDENTIALS_KEY_FILE", DEFAULT_KEY_FILE))


def load_master_key() -> bytes:
    path = key_file_path()
    try:
        info = path.lstat()
    except OSError as exc:
        raise SecretStorageError("secret_encryption_key_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SecretStorageError("secret_encryption_key_must_be_regular_file")
    if os.name == "posix" and info.st_mode & 0o077:
        raise SecretStorageError("secret_encryption_key_permissions_too_open")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SecretStorageError("secret_encryption_key_unreadable") from exc

    if len(raw) == KEY_BYTES:
        key = raw
    else:
        try:
            key = base64.b64decode(raw.strip(), validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise SecretStorageError("secret_encryption_key_invalid") from exc
    if len(key) != KEY_BYTES:
        raise SecretStorageError("secret_encryption_key_invalid")
    return key


def is_envelope(value: Any) -> bool:
    return isinstance(value, dict) and value.get(ENVELOPE_FIELD) == ENVELOPE_VERSION


def encrypt_secret(value: str, *, context: str) -> Any:
    if not isinstance(value, str):
        raise SecretStorageError("secret_value_invalid")
    if value == "":
        return ""
    key = load_master_key()
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), context.encode("utf-8"))
    return {
        ENVELOPE_FIELD: ENVELOPE_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_secret(value: Any, *, context: str) -> Any:
    if not is_envelope(value):
        return value
    key = load_master_key()
    try:
        nonce = base64.b64decode(value["nonce"], validate=True)
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        if len(nonce) != NONCE_BYTES:
            raise ValueError("bad nonce length")
        return AESGCM(key).decrypt(nonce, ciphertext, context.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        raise SecretStorageError("secret_encryption_integrity_failure") from exc


def seal_panel_state(data: dict) -> dict:
    """Return a copy of state with plaintext SSH/TOTP secrets sealed for disk."""
    import copy

    stored = copy.deepcopy(data)
    for server in stored.get("servers", []):
        if not isinstance(server, dict):
            continue
        for field in ("password", "private_key"):
            value = server.get(field, "")
            if value and not is_envelope(value):
                server[field] = encrypt_secret(value, context=f"prvtpro:ssh:{field}:v1")
    for user in stored.get("users", []):
        if not isinstance(user, dict):
            continue
        mfa = user.get("mfa")
        if not isinstance(mfa, dict):
            continue
        value = mfa.get("totp_secret", "")
        if value and not is_envelope(value):
            user_id = str(user.get("id", ""))
            mfa["totp_secret"] = encrypt_secret(
                value, context=f"prvtpro:user:{user_id}:totp:v1")
    return stored


def unseal_panel_state(data: dict) -> dict:
    """Decrypt versioned envelopes in memory while leaving legacy strings intact."""
    for server in data.get("servers", []):
        if not isinstance(server, dict):
            continue
        for field in ("password", "private_key"):
            if is_envelope(server.get(field)):
                server[field] = decrypt_secret(
                    server[field], context=f"prvtpro:ssh:{field}:v1")
    for user in data.get("users", []):
        if not isinstance(user, dict):
            continue
        mfa = user.get("mfa")
        if not isinstance(mfa, dict) or not is_envelope(mfa.get("totp_secret")):
            continue
        user_id = str(user.get("id", ""))
        mfa["totp_secret"] = decrypt_secret(
            mfa["totp_secret"], context=f"prvtpro:user:{user_id}:totp:v1")
    return data


def has_legacy_plaintext_secrets(data: dict) -> bool:
    for server in data.get("servers", []):
        if isinstance(server, dict) and any(
            isinstance(server.get(field), str) and server.get(field)
            for field in ("password", "private_key")
        ):
            return True
    for user in data.get("users", []):
        mfa = user.get("mfa") if isinstance(user, dict) else None
        if isinstance(mfa, dict) and isinstance(mfa.get("totp_secret"), str) and mfa["totp_secret"]:
            return True
    return False


def seal_legacy_recovery_snapshots(directory: str | Path) -> int:
    """Encrypt historical before_base64 snapshots so panel archives stay sealed.

    The snapshot hash remains unchanged because it describes the original state
    bytes. The RecoveryStore replay logic does not consume the embedded snapshot;
    this module provides an authenticated decoder for offline recovery tooling.
    """
    from peer_recovery import atomic_json

    root = Path(directory)
    if not root.exists():
        return 0
    if root.is_symlink() or not root.is_dir():
        raise SecretStorageError("unsafe_recovery_directory")
    if os.name == "posix" and root.stat().st_mode & 0o077:
        raise SecretStorageError("recovery_directory_permissions_too_open")
    migrated = 0
    for path in sorted(root.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise SecretStorageError("unsafe_recovery_snapshot")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise SecretStorageError("invalid_recovery_snapshot") from exc
        if not isinstance(record, dict):
            raise SecretStorageError("invalid_recovery_snapshot")
        snapshot = record.get("before_base64")
        if isinstance(snapshot, str):
            record["before_base64"] = encrypt_secret(
                snapshot, context=f"prvtpro:recovery:{path.stem}:before:v1")
            record["before_base64_encrypted"] = ENVELOPE_VERSION
            atomic_json(path, record)
            migrated += 1
        elif snapshot is not None and not is_envelope(snapshot):
            raise SecretStorageError("invalid_recovery_snapshot")
    return migrated


def decode_recovery_snapshot(record: dict, operation_id: str) -> bytes:
    """Decode a legacy or encrypted recovery snapshot for offline recovery."""
    snapshot = record.get("before_base64")
    if is_envelope(snapshot):
        snapshot = decrypt_secret(
            snapshot, context=f"prvtpro:recovery:{operation_id}:before:v1")
    if not isinstance(snapshot, str):
        raise SecretStorageError("recovery_snapshot_unavailable")
    try:
        return base64.b64decode(snapshot, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SecretStorageError("invalid_recovery_snapshot") from exc
