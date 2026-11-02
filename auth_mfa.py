"""Admin MFA primitives: WebAuthn passkeys, RFC 6238 TOTP, recovery codes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

CHALLENGE_TTL_SECONDS = 180
RECOVERY_CODE_COUNT = 10
_TOTP_PERIOD = 30
_TOTP_DIGITS = 6


class MFAError(ValueError):
    pass


class OneTimeChallengeStore:
    """Process-local bounded one-shot challenge store; restart invalidates challenges."""

    def __init__(self, max_entries: int = 4096, ttl: int = CHALLENGE_TTL_SECONDS):
        self._items: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._ttl = ttl

    def issue(self, challenge: bytes) -> str:
        now = time.monotonic()
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._items = {k: v for k, v in self._items.items() if v[1] > now}
            if len(self._items) >= self._max_entries:
                oldest = min(self._items, key=lambda k: self._items[k][1])
                self._items.pop(oldest, None)
            self._items[token] = (bytes(challenge), now + self._ttl)
        return token

    def take(self, token: str) -> bytes:
        with self._lock:
            item = self._items.pop(token, None)
        if item is None or item[1] <= time.monotonic():
            raise MFAError("mfa_challenge_expired")
        return item[0]


CHALLENGES = OneTimeChallengeStore()


def webauthn_config() -> tuple[str, str]:
    rp_id = os.environ.get("WEBAUTHN_RP_ID", "").strip().lower().rstrip(".")
    origin = os.environ.get("WEBAUTHN_ORIGIN", "").strip().rstrip("/")
    if not rp_id or not origin:
        raise MFAError("webauthn_origin_not_configured")
    parsed = urlparse(origin)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise MFAError("webauthn_origin_invalid")
    host = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise MFAError("webauthn_origin_invalid") from exc
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not loopback:
        raise MFAError("webauthn_requires_https")
    if host != rp_id and not host.endswith("." + rp_id):
        raise MFAError("webauthn_rp_id_must_match_origin")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise MFAError("webauthn_origin_invalid")
    normalized_origin = f"{parsed.scheme}://{host}{':' + str(port) if port else ''}"
    return rp_id, normalized_origin


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 4096:
        raise MFAError("webauthn_credential_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise MFAError("webauthn_credential_invalid") from exc


def passkey_record_key(credential_id: str) -> str:
    return credential_id.rstrip("=")


def registration_options(user: dict, passkeys: list[dict]) -> tuple[str, dict]:
    rp_id, _ = webauthn_config()
    exclude = []
    for record in passkeys:
        try:
            exclude.append(PublicKeyCredentialDescriptor(id=b64url_decode(record["credential_id"])))
        except (KeyError, MFAError):
            continue
    username = str(user.get("username", "admin"))[:128]
    user_id = str(user.get("id", "")).encode("utf-8")
    if not user_id or len(user_id) > 64:
        raise MFAError("webauthn_user_id_invalid")
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Amnezia Web Panel",
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude,
    )
    challenge_id = CHALLENGES.issue(options.challenge)
    return challenge_id, json.loads(options_to_json(options))


def authentication_options(passkeys: list[dict]) -> tuple[str, dict]:
    rp_id, _ = webauthn_config()
    allowed = []
    for record in passkeys:
        try:
            allowed.append(PublicKeyCredentialDescriptor(id=b64url_decode(record["credential_id"])))
        except (KeyError, MFAError):
            continue
    if not allowed:
        raise MFAError("webauthn_passkey_not_enrolled")
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = CHALLENGES.issue(options.challenge)
    return challenge_id, json.loads(options_to_json(options))


def verify_passkey_registration(credential: dict, challenge_id: str) -> dict:
    rp_id, origin = webauthn_config()
    challenge = CHALLENGES.take(challenge_id)
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )
    transports = credential.get("response", {}).get("transports", [])
    if not isinstance(transports, list):
        transports = []
    return {
        "credential_id": b64url_encode(verified.credential_id),
        "public_key": b64url_encode(verified.credential_public_key),
        "sign_count": int(verified.sign_count),
        "transports": [str(x)[:32] for x in transports[:8] if isinstance(x, str)],
        "created_at": int(time.time()),
    }


def verify_passkey_authentication(credential: dict, challenge_id: str,
                                  passkey: dict) -> int:
    rp_id, origin = webauthn_config()
    challenge = CHALLENGES.take(challenge_id)
    if passkey_record_key(str(credential.get("id", ""))) != passkey_record_key(
        str(passkey.get("credential_id", ""))
    ):
        raise MFAError("webauthn_credential_not_registered")
    result = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=b64url_decode(passkey["public_key"]),
        credential_current_sign_count=int(passkey.get("sign_count", 0)),
        require_user_verification=True,
    )
    return int(result.new_sign_count)


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_uri(secret: str, username: str, issuer: str = "Amnezia Web Panel") -> str:
    from urllib.parse import quote, urlencode

    label = quote(f"{issuer}:{username}", safe="")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                       "digits": str(_TOTP_DIGITS), "period": str(_TOTP_PERIOD)})
    return f"otpauth://totp/{label}?{query}"


def _totp_at(secret: str, counter: int) -> str:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** _TOTP_DIGITS)
    return f"{value:0{_TOTP_DIGITS}d}"


def verify_totp(secret: str, code: str, *, now: float | None = None,
                last_counter: int = -1) -> int | None:
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        return None
    counter = int((time.time() if now is None else now) // _TOTP_PERIOD)
    for candidate in (counter, counter - 1, counter + 1):
        if candidate <= last_counter:
            continue
        if hmac.compare_digest(_totp_at(secret, candidate), code):
            return candidate
    return None


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    return [secrets.token_hex(8) for _ in range(count)]


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", str(code)).lower()


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    if len(normalized) != 16:
        return ""
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def consume_recovery_code(mfa: dict, code: str) -> bool:
    candidate = hash_recovery_code(code)
    if not candidate:
        return False
    stored = mfa.get("recovery_code_hashes", [])
    if not isinstance(stored, list):
        return False
    matched = next((value for value in stored
                    if isinstance(value, str) and hmac.compare_digest(value, candidate)), None)
    if matched is None:
        return False
    mfa["recovery_code_hashes"] = [value for value in stored if value != matched]
    return True


def mfa_enrolled(mfa: dict | None) -> bool:
    if not isinstance(mfa, dict):
        return False
    has_totp = isinstance(mfa.get("totp_secret"), str) and bool(mfa.get("totp_secret"))
    has_passkey = isinstance(mfa.get("passkeys"), list) and bool(mfa.get("passkeys"))
    return bool(mfa.get("enabled") and (has_totp or has_passkey))
