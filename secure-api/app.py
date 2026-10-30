"""
secure-api —— 安全 REST API（作业第一部分）

演示三类安全防护：
  1) 认证安全：bcrypt 密码哈希 + JWT 无状态鉴权；
  2) SQL 注入防护：全程参数化查询（? 占位符），绝无字符串拼接；
  3) 存储型 XSS 防护：内容原样入库，渲染时由 Jinja2 自动转义。

运行：
    python init_db.py
    python app.py
"""
import os
import sqlite3

import bcrypt
from flask import Flask, jsonify, render_template_string, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

app = Flask(__name__)

# JWT 密钥：生产环境务必从环境变量读取，严禁硬编码提交到仓库。
# 默认值仅用于本地开发（≥32 字节以满足 HS256 建议，避免 InsecureKeyLengthWarning）。
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "dev-only-secret-key-change-me-0123456789abcdef"
)
# 数据库路径：测试时可注入临时库，避免污染真实 app.db
app.config["DATABASE"] = os.environ.get("SECURE_API_DB", "app.db")

jwt = JWTManager(app)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    # bcrypt 自带盐值，cost=12 提高暴力破解成本
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 1) 注册：bcrypt 哈希 + 参数化查询
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"msg": "用户名和密码不能为空"}), 400
    if len(password) > 72:
        # bcrypt 只使用前 72 字节，超长直接拒绝
        return jsonify({"msg": "密码过长（最多 72 字符）"}), 400

    db = get_db()
    try:
        # 参数化查询：? 占位符。用户名即使包含 ' OR '1'='1 也只会被当作字面量。
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"msg": "用户名已存在"}), 409
    finally:
        db.close()

    return jsonify({"msg": "注册成功"}), 201


# ---------------------------------------------------------------------------
# 2) 登录：参数化查询防 SQLi，bcrypt 校验密码，成功后签发 JWT
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"msg": "用户名和密码不能为空"}), 400

    db = get_db()
    # 绝不可写成 f"... WHERE username = '{username}'"：
    # 那样的话 "' OR '1'='1" 即可绕过登录。参数化查询从根上杜绝了这类注入。
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    db.close()

    if row is None or not verify_password(password, row["password_hash"]):
        # 统一返回同样的错误信息，避免通过提示差异枚举用户名
        return jsonify({"msg": "用户名或密码错误"}), 401

    token = create_access_token(identity=str(row["id"]))
    return jsonify({"access_token": token, "username": row["username"]}), 200


# ---------------------------------------------------------------------------
# 3) 受保护接口：演示 JWT 鉴权
# ---------------------------------------------------------------------------
@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    db = get_db()
    row = db.execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    db.close()
    if row is None:
        return jsonify({"msg": "用户不存在"}), 404
    return jsonify({"id": row["id"], "username": row["username"]}), 200


# ---------------------------------------------------------------------------
# 4) 发布文章：内容原样入库（存储型 XSS 的“存储”环节）
# ---------------------------------------------------------------------------
@app.route("/posts", methods=["POST"])
@jwt_required()
def create_post():
    user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = data.get("content") or ""

    if not title or not content:
        return jsonify({"msg": "标题和内容不能为空"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, user_id),
    )
    db.commit()
    db.close()
    return jsonify({"msg": "发布成功"}), 201


# ---------------------------------------------------------------------------
# 5) 文章列表：渲染时自动转义，阻断存储型 XSS
# ---------------------------------------------------------------------------
@app.route("/posts", methods=["GET"])
def list_posts():
    db = get_db()
    rows = db.execute(
        """
        SELECT p.title, p.content, u.username
        FROM posts p JOIN users u ON p.author_id = u.id
        ORDER BY p.id DESC
        """
    ).fetchall()
    db.close()

    # Jinja2 默认开启自动转义：{{ post['content'] }} 会把 <script> 输出成
    # &lt;script&gt;，浏览器只会当作纯文本显示，不会执行——从而阻断存储型 XSS。
    html = render_template_string(
        """
        <!doctype html>
        <meta charset="utf-8">
        <title>文章列表</title>
        <h1>文章列表</h1>
        {% for post in posts %}
          <article>
            <h2>{{ post['title'] }}</h2>
            <p>{{ post['content'] }}</p>
            <small>作者：{{ post['username'] }}</small>
          </article>
          <hr>
        {% endfor %}
        """,
        posts=rows,
    )
    return html


if __name__ == "__main__":
    # debug=False：生产环境若开启 debug 会暴露 Werkzeug 调试器，属高危配置
    app.run(host="127.0.0.1", port=5000, debug=False)
