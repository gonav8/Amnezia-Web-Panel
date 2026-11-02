import time

import pytest

from auth_mfa import (
    MFAError,
    OneTimeChallengeStore,
    _totp_at,
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_code,
    new_totp_secret,
    verify_totp,
    webauthn_config,
)


def test_totp_matches_rfc_6238_sha1_truncation_and_prevents_replay():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert _totp_at(secret, 1) == "287082"
    assert verify_totp(secret, "287082", now=30, last_counter=-1) == 1
    assert verify_totp(secret, "287082", now=30, last_counter=1) is None
    assert verify_totp(secret, "bad", now=30, last_counter=-1) is None


def test_recovery_codes_are_hashed_and_single_use():
    codes = generate_recovery_codes(3)
    mfa = {"recovery_code_hashes": [hash_recovery_code(code) for code in codes]}
    assert all(len(code) == 16 for code in codes)
    assert consume_recovery_code(mfa, codes[0]) is True
    assert consume_recovery_code(mfa, codes[0]) is False
    assert len(mfa["recovery_code_hashes"]) == 2


def test_web_authn_challenges_are_one_time_and_expire():
    store = OneTimeChallengeStore(ttl=60)
    token = store.issue(b"challenge")
    assert store.take(token) == b"challenge"
    with pytest.raises(MFAError):
        store.take(token)


def test_passkey_origin_requires_exact_https_origin_and_matching_rp(monkeypatch):
    monkeypatch.setenv("WEBAUTHN_RP_ID", "example.com")
    monkeypatch.setenv("WEBAUTHN_ORIGIN", "https://panel.example.com:5001")
    assert webauthn_config() == ("example.com", "https://panel.example.com:5001")
    monkeypatch.setenv("WEBAUTHN_ORIGIN", "http://panel.example.com")
    with pytest.raises(MFAError, match="requires_https"):
        webauthn_config()
    monkeypatch.setenv("WEBAUTHN_ORIGIN", "https://attacker.test")
    with pytest.raises(MFAError, match="rp_id"):
        webauthn_config()


def test_totp_secret_has_expected_entropy_length():
    secret = new_totp_secret()
    assert len(secret) == 32
    assert _totp_at(secret, int(time.time() // 30)).isdigit()
