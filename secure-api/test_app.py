"""
pytest 自动化测试：覆盖认证、SQL 注入防护、JWT 鉴权、存储型 XSS 防护。
CI 流水线（.github/workflows/ci.yml）会执行本文件。
"""
import os
import tempfile

import pytest

import app as app_module
from init_db import init_db


@pytest.fixture()
def client():
    # 每个测试用独立的临时数据库，避免污染真实 app.db
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path)

    app_module.app.config["DATABASE"] = db_path
    app_module.app.config["TESTING"] = True

    with app_module.app.test_client() as c:
        yield c

    os.remove(db_path)


def _login(client, username="alice", password="Alice#2026!"):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.get_json()["access_token"]


def test_login_success_returns_jwt(client):
    resp = client.post(
        "/auth/login", json={"username": "alice", "password": "Alice#2026!"}
    )
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_login_wrong_password(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid credentials"


def test_login_sql_injection_blocked(client):
    # 若登录用字符串拼接 SQL，该 payload 会绕过认证；参数化查询下应返回 401
    resp = client.post(
        "/auth/login", json={"username": "alice' OR '1'='1", "password": "x"}
    )
    assert resp.status_code == 401


def test_api_data_requires_token(client):
    resp = client.get("/api/data")
    assert resp.status_code == 401


def test_api_data_empty_with_token(client):
    token = _login(client)
    resp = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json() == {"data": []}


def test_create_post_requires_auth(client):
    resp = client.post("/api/posts", json={"title": "t", "content": "c"})
    assert resp.status_code == 401


def test_create_post_missing_fields(client):
    token = _login(client)
    resp = client.post(
        "/api/posts", json={"title": "", "content": ""},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_stored_xss_is_escaped(client):
    token = _login(client)

    # 攻击者试图注入一段脚本作为标题
    xss = "<script>alert(1)</script>"
    create = client.post(
        "/api/posts",
        json={"title": xss, "content": "xss test"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create.status_code == 201

    # 读回时 title 应被转义，而不是原样返回可执行的 <script>
    data = client.get(
        "/api/data", headers={"Authorization": f"Bearer {token}"}
    ).get_json()
    title = data["data"][0]["title"]
    assert title == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert "<script>" not in title
