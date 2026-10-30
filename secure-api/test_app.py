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


def _register_and_login(client, username="alice", password="Alice#2026!"):
    """返回 (access_token, headers)"""
    client.post("/register", json={"username": username, "password": password})
    resp = client.post("/login", json={"username": username, "password": password})
    token = resp.get_json()["access_token"]
    return token, {"Authorization": f"Bearer {token}"}


def test_register_success(client):
    resp = client.post("/register", json={"username": "bob", "password": "Bob#1234!"})
    assert resp.status_code == 201


def test_register_duplicate(client):
    client.post("/register", json={"username": "alice", "password": "Alice#2026!"})
    resp = client.post("/register", json={"username": "alice", "password": "Alice#2026!"})
    assert resp.status_code == 409


def test_login_success_returns_jwt(client):
    resp = client.post("/login", json={"username": "alice", "password": "Alice#2026!"})
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_login_wrong_password(client):
    resp = client.post("/login", json={"username": "alice", "password": "wrong-password"})
    assert resp.status_code == 401


def test_login_sql_injection_blocked(client):
    # 若登录用字符串拼接 SQL，该 payload 会绕过认证；参数化查询下应返回 401
    payload = {"username": "alice' OR '1'='1", "password": "whatever"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 401


def test_me_without_token(client):
    resp = client.get("/me")
    assert resp.status_code == 401


def test_me_with_token(client):
    _, headers = _register_and_login(client)
    resp = client.get("/me", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_create_post_requires_auth(client):
    resp = client.post("/posts", json={"title": "t", "content": "c"})
    assert resp.status_code == 401


def test_stored_xss_is_escaped(client):
    _, headers = _register_and_login(client)

    # 攻击者试图注入一段脚本
    xss = "<script>alert('xss')</script>"
    create = client.post(
        "/posts", json={"title": "恶意文章", "content": xss}, headers=headers
    )
    assert create.status_code == 201

    # 渲染列表页时，脚本应被转义为纯文本，不应出现可执行的 <script> 标签
    html = client.get("/posts").get_data(as_text=True)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html
