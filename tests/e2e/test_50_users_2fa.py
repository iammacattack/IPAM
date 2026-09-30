"""Local users, roles, 2FA and step-up (the PAMdora model), through the same API the UI uses."""

from __future__ import annotations

import uuid

import bcrypt
import httpx
import psycopg
import pyotp
import pytest

from helpers import API_KEY, BASE_URL, DATABASE_URL

PASSWORD = "Correct-Horse-42"
UI = {"X-Requested-With": "IPAM-UI", "X-Client-Name": "pytest/ui"}


def make_user(roles: list[str], *, must_change: bool = False, password: str = PASSWORD) -> str:
    name = f"pt-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        uid = conn.execute(
            "INSERT INTO app_user (username, password_hash, must_change_password, created_by) VALUES (%s, %s, %s, 'pytest') RETURNING user_id",
            (name, bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode(), must_change),
        ).fetchone()[0]
        for r in roles:
            conn.execute("INSERT INTO user_role (user_id, role_key) VALUES (%s, %s)", (uid, r))
    return name


def browser() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, headers=UI, timeout=30)


def sign_in(c: httpx.Client, username: str, password: str = PASSWORD) -> httpx.Response:
    return c.post("/auth/login", json={"username": username, "password": password})


def enrol(c: httpx.Client) -> tuple[pyotp.TOTP, list[str]]:
    r = c.post("/auth/mfa/enrol")
    assert r.status_code == 200, r.text
    assert r.json()["qrSvg"].startswith("data:image/svg+xml;base64,")
    totp = pyotp.TOTP(r.json()["secret"])
    r = c.post("/auth/mfa/enrol/verify", json={"code": totp.now()})
    assert r.status_code == 200, r.text
    codes = r.json()["backupCodes"]
    assert len(codes) == 10 and r.json()["user"]["mfaEnrolled"] is True
    return totp, codes


@pytest.fixture(scope="module", autouse=True)
def cleanup():
    yield
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("DELETE FROM app_user WHERE username LIKE 'pt-%'")
        conn.execute("DELETE FROM api_key WHERE owner = 'pytest'")


def test_wrong_password_and_unknown_user_look_the_same():
    user = make_user(["viewer"])
    with browser() as c:
        a = sign_in(c, user, "Wrong-Password-1")
        b = sign_in(c, "pt-nobody", "Wrong-Password-1")
    assert a.status_code == b.status_code == 401
    assert a.json()["code"] == b.json()["code"] == "IPAM-LOGIN-FAILED"


def test_lockout_after_repeated_failures():
    user = make_user(["viewer"])
    with browser() as c:
        for _ in range(5):
            assert sign_in(c, user, "Wrong-Password-1").status_code == 401
        r = sign_in(c, user)  # even the right password is refused while locked
    assert r.status_code == 429 and r.json()["code"] == "IPAM-ACCOUNT-LOCKED"


def test_session_cookie_is_httponly_and_strict():
    user = make_user(["viewer"])
    with browser() as c:
        r = sign_in(c, user)
        assert r.status_code == 200 and r.json()["mfaRequired"] is False
        cookie = r.headers["set-cookie"].lower()
        assert "ipam_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        assert c.get("/sites").status_code == 200
        me = c.get("/auth/me").json()
        assert me["roles"] == [{"key": "viewer", "name": "Viewer"}] and me["permissions"] == ["read"]
        # a viewer can't reserve
        r = c.post("/sites", json={"siteCode": "PT1", "templateKey": "EXAMPLE-NET-10"})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-PERMISSION-DENIED"
        c.post("/auth/logout")
        assert c.get("/sites").status_code == 401


def test_cookie_writes_need_the_ui_header():
    user = make_user(["operator"])
    with browser() as c:
        sign_in(c, user)
        r = c.post("/sites?dryRun=true", json={"siteCode": "PT2", "templateKey": "EXAMPLE-NET-10"}, headers={"X-Requested-With": ""})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-CSRF"
        r = c.post("/sites?dryRun=true", json={"siteCode": "PT2", "templateKey": "EXAMPLE-NET-10"})
        assert r.status_code == 200


def test_operator_flow_with_step_up():
    user = make_user(["operator"])
    with browser() as c:
        sign_in(c, user)
        r = c.post("/sites", json={"siteCode": "PT3", "templateKey": "EXAMPLE-NET-10"})
        assert r.status_code == 201, r.text  # reserving needs no step-up
        rid = r.json()["reservation"]["reservationId"]

        # confirming does, and there's no authenticator yet
        r = c.post("/sites/PT3:confirm", json={"reservationId": rid})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-MFA-ENROLMENT-REQUIRED"

        totp, codes = enrol(c)
        # enrolment counts as a fresh step-up, so age it out to test the prompt
        with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
            conn.execute("UPDATE user_session s SET step_up_at = now() - interval '1 hour' FROM app_user u WHERE u.user_id = s.user_id AND u.username = %s", (user,))

        r = c.post("/sites/PT3:confirm", json={"reservationId": rid})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-STEP-UP-REQUIRED"
        r = c.post("/sites/PT3:confirm", json={"reservationId": rid}, headers={"X-IPAM-2FA": "000000"})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-STEP-UP-FAILED"
        # the enrolment code has already been used, so replaying it fails too
        r = c.post("/sites/PT3:confirm", json={"reservationId": rid}, headers={"X-IPAM-2FA": totp.now()})
        assert r.status_code == 403 and r.json()["code"] == "IPAM-STEP-UP-FAILED"
        # a backup code works, once
        r = c.post("/sites/PT3:confirm", json={"reservationId": rid}, headers={"X-IPAM-2FA": codes[0]})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "allocated"

        audit = httpx.get(f"{BASE_URL}/audit", params={"requestId": r.headers["X-Request-Id"]}, headers={"X-API-Key": API_KEY}).json()[0]
        assert audit["actorType"] == "user" and audit["actorId"] == f"user:{user}"
        assert "step-up: backup-code" in audit["authMethod"]

        # inside the window, the next high-risk action doesn't prompt
        r2 = c.post("/sites", json={"siteCode": "PT4", "templateKey": "EXAMPLE-NET-10"})
        assert c.post("/sites/PT4:release").status_code == 200


def test_sign_in_with_2fa():
    user = make_user(["viewer"])
    with browser() as c:
        sign_in(c, user)
        _, codes = enrol(c)
        c.post("/auth/logout")

        r = sign_in(c, user)
        assert r.status_code == 202 and r.json()["mfaRequired"] is True
        # half signed-in sessions can't do anything
        r = c.get("/sites")
        assert r.status_code == 401 and r.json()["code"] == "IPAM-MFA-REQUIRED"
        assert c.post("/auth/mfa/verify", json={"code": "123456"}).json()["code"] == "IPAM-MFA-FAILED"
        r = c.post("/auth/mfa/verify", json={"code": codes[1].lower()})  # backup codes aren't case-sensitive
        assert r.status_code == 200, r.text
        assert c.get("/sites").status_code == 200
        # a used backup code can't be used again
        c.post("/auth/logout")
        sign_in(c, user)
        assert c.post("/auth/mfa/verify", json={"code": codes[1]}).status_code == 401


def test_first_sign_in_forces_password_change_then_2fa_for_admins():
    admin = make_user(["admin"], must_change=True)
    with browser() as c:
        sign_in(c, admin)
        r = c.get("/sites")
        assert r.status_code == 403 and r.json()["code"] == "IPAM-PASSWORD-CHANGE-REQUIRED"
        assert c.get("/auth/me").json()["mustChangePassword"] is True
        r = c.post("/auth/change-password", json={"currentPassword": PASSWORD, "newPassword": "short"})
        assert r.json()["code"] == "IPAM-PASSWORD-WEAK"
        r = c.post("/auth/change-password", json={"currentPassword": PASSWORD, "newPassword": "Another-Good-Pass-7"})
        assert r.status_code == 200 and r.json()["mustChangePassword"] is False
        # admins must enrol before anything else
        r = c.get("/sites")
        assert r.status_code == 403 and r.json()["code"] == "IPAM-MFA-ENROLMENT-REQUIRED"
        enrol(c)
        assert c.get("/sites").status_code == 200


def test_admin_manages_users_and_keys():
    admin = make_user(["admin"])
    with browser() as c:
        sign_in(c, admin)
        _, codes = enrol(c)  # enrolment also opens the step-up window
        r = c.post("/users", json={"username": "PT-Newbie", "fullName": "New Person", "roles": ["designer"]})
        assert r.status_code == 201, r.text
        new = r.json()
        assert new["username"] == "pt-newbie" and new["roles"] == ["designer"] and new["temporaryPassword"]
        assert c.post("/users", json={"username": "pt-newbie", "roles": []}).json()["code"] == "IPAM-USER-EXISTS"
        assert c.post("/users", json={"username": "pt-x", "roles": ["wizard"]}).json()["code"] == "IPAM-ROLE-UNKNOWN"

        # the new user must change the temporary password
        with browser() as n:
            assert sign_in(n, "pt-newbie", new["temporaryPassword"]).status_code == 200
            assert n.get("/templates").json()["code"] == "IPAM-PASSWORD-CHANGE-REQUIRED"

        r = c.patch("/users/pt-newbie", json={"roles": ["viewer"], "status": "disabled"})
        assert r.status_code == 200 and r.json()["roles"] == ["viewer"] and r.json()["status"] == "disabled"
        with browser() as n:
            assert sign_in(n, "pt-newbie", new["temporaryPassword"]).status_code == 401

        r = c.post("/api-keys", json={"owner": "pytest", "purpose": "e2e key", "clientName": "pytest", "scopes": ["read"], "expiresInDays": 1})
        assert r.status_code == 201, r.text
        key = r.json()["key"]
        assert httpx.get(f"{BASE_URL}/templates", headers={"X-API-Key": key}).status_code == 200
        assert httpx.post(f"{BASE_URL}/sites", json={"siteCode": "PT9", "templateKey": "EXAMPLE-NET-10"}, headers={"X-API-Key": key}).status_code == 403
        c.post(f"/api-keys/{r.json()['prefix']}:revoke").raise_for_status()
        assert httpx.get(f"{BASE_URL}/templates", headers={"X-API-Key": key}).json()["code"] == "IPAM-KEY-REVOKED"

        roles = c.get("/roles").json()
        assert {r["key"] for r in roles["roles"]} >= {"viewer", "designer", "operator", "auditor", "admin"}


def test_users_admin_needs_the_permission():
    user = make_user(["designer"])
    with browser() as c:
        sign_in(c, user)
        assert c.get("/users").json()["code"] == "IPAM-PERMISSION-DENIED"
        assert c.get("/audit").json()["code"] == "IPAM-PERMISSION-DENIED"
