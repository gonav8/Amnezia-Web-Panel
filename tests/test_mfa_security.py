import time

from fastapi.testclient import TestClient

import app as panel
from auth_mfa import _totp_at, new_totp_secret


def _admin(password="correct horse battery staple", mfa=None):
    return {
        "id": "mfa-admin-1",
        "username": "admin",
        "password_hash": panel.hash_password(password),
        "role": "admin",
        "enabled": True,
        "mfa": mfa or {},
    }


def test_production_default_requires_mfa_enrollment(monkeypatch):
    monkeypatch.setenv("PANEL_ADMIN_MFA_REQUIRED", "1")
    data = {"users": [_admin()], "servers": [], "settings": {}}
    monkeypatch.setattr(panel, "load_data", lambda: data)
    monkeypatch.setattr(panel, "save_data", lambda _data: None)

    with TestClient(panel.app) as client:
        response = client.post("/api/auth/login", json={
            "username": "admin", "password": "correct horse battery staple"})
        assert response.status_code == 200
        assert response.json()["status"] == "mfa_setup_required"
        page = client.get("/security/setup")
        assert page.status_code == 200
        assert "Administrator MFA is required" in page.text
        assert client.get("/api/auth/mfa/status").status_code == 403


def test_password_login_for_enrolled_admin_requires_and_accepts_totp(monkeypatch):
    monkeypatch.setenv("PANEL_ADMIN_MFA_REQUIRED", "1")
    secret = new_totp_secret()
    current_counter = int(time.time() // 30)
    data = {"users": [_admin(mfa={
        "enabled": True,
        "totp_secret": secret,
        "totp_last_counter": current_counter - 1,
        "passkeys": [],
        "recovery_code_hashes": [],
    })], "servers": [], "settings": {}}
    monkeypatch.setattr(panel, "load_data", lambda: data)
    monkeypatch.setattr(panel, "save_data", lambda _data: None)

    with TestClient(panel.app) as client:
        response = client.post("/api/auth/login", json={
            "username": "admin", "password": "correct horse battery staple"})
        assert response.status_code == 200
        assert response.json()["status"] == "mfa_required"
        options = client.get("/api/auth/mfa/login/options")
        assert options.status_code == 200
        assert options.json()["totp_available"] is True
        assert options.headers["cache-control"] == "no-store, private"
        code = _totp_at(secret, current_counter)
        verify = client.post("/api/auth/mfa/login/code", json={"method": "totp", "code": code})
        assert verify.status_code == 200
        assert verify.json()["role"] == "admin"
        assert client.get("/api/auth/mfa/status").status_code == 200


def test_admin_sensitive_routes_require_recent_factor(monkeypatch):
    monkeypatch.setenv("PANEL_ADMIN_MFA_REQUIRED", "1")
    data = {"users": [_admin(mfa={
        "enabled": True, "totp_secret": new_totp_secret(), "totp_last_counter": -1,
        "passkeys": [], "recovery_code_hashes": [],
    })], "servers": [], "settings": {}}
    monkeypatch.setattr(panel, "load_data", lambda: data)
    monkeypatch.setattr(panel, "save_data", lambda _data: None)

    with TestClient(panel.app) as client:
        login = client.post("/api/auth/login", json={
            "username": "admin", "password": "correct horse battery staple"})
        assert login.json()["status"] == "mfa_required"
        client.get("/api/auth/mfa/login/options")
        counter = int(time.time() // 30)
        code = _totp_at(data["users"][0]["mfa"]["totp_secret"], counter)
        assert client.post("/api/auth/mfa/login/code", json={"code": code}).status_code == 200
        # A stale mfa_at is still an authenticated session but cannot authorize
        # privileged SSH/backup operations until step-up succeeds.
        request = panel.Request({"type": "http", "method": "POST", "path": "/api/servers/add",
                                 "headers": [], "query_string": b"", "server": ("test", 80),
                                 "client": ("127.0.0.1", 1234), "scheme": "http",
                                 "root_path": "", "http_version": "1.1",
                                 "session": {"user_id": "mfa-admin-1", "mfa_at": int(time.time()) - 301}})
        gate = panel._require_recent_admin_mfa(request)
        assert gate.status_code == 403
        assert b"mfa_step_up_required" in gate.body
