"""
secure-api —— 安全 REST API（作业第一部分）

三个端点：
  1) POST /auth/login   —— 登录，bcrypt 校验 + 签发 JWT
  2) GET  /api/data     —— JWT 保护，返回当前用户文章（XSS 转义）
  3) POST /api/posts    —— JWT 保护，发布文章（参数化查询防 SQLi）

安全得分点：
  - 认证（1 分）：登录成功签发 JWT，@jwt_required() 保护 /api/data 与 /api/posts，
    密码以 bcrypt cost=12 哈希存储
  - SQLi 防护（0.5 分）：所有 SQL 均使用 ? 参数化占位符，无 f-string/%/.format 拼接
  - XSS 防护（0.5 分）：GET /api/data 返回前用 markupsafe.escape() 做 HTML 实体编码

运行：
    python init_db.py
    python app.py
"""
import os
import sqlite3

import bcrypt
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from markupsafe import escape

app = Flask(__name__)

# JWT 密钥：生产环境务必从环境变量读取，严禁硬编码提交到仓库
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "change-me-in-production-use-env-var"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 900  # 15 分钟
# 数据库路径：测试时可注入临时库，避免污染真实 app.db
app.config["DATABASE"] = os.environ.get("SECURE_API_DB", "app.db")

jwt = JWTManager(app)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


# ---------- 端点 1：POST /auth/login ----------
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    # 参数化查询：? 是绑定参数，用户输入永远不会成为 SQL 语法的一部分。
    # 若写成 f"... WHERE username = '{username}'"，' OR '1'='1 即可绕过登录。
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    # 用户不存在与密码错误统一返回同一句话，避免用户名枚举
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(identity=str(row["id"]))
    return jsonify({"access_token": token})


# ---------- 端点 2：GET /api/data（JWT 保护） ----------
@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_data():
    user_id = get_jwt_identity()
    conn = get_db()
    rows = conn.execute(
        "SELECT id, title, content FROM posts WHERE author_id = ?",
        (user_id,),
    ).fetchall()
    conn.close()

    result = [
        {
            "id": r["id"],
            # XSS 转义：返回前对用户数据做 HTML 实体编码，
            # <script> 会变成 &lt;script&gt;，浏览器不会执行
            "title": escape(r["title"]),
            "content": escape(r["content"]),
        }
        for r in rows
    ]
    return jsonify({"data": result})


# ---------- 端点 3：POST /api/posts（JWT 保护，演示存储型 XSS） ----------
@app.route("/api/posts", methods=["POST"])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    title = data.get("title", "")
    content = data.get("content", "")

    if not title or not content:
        return jsonify({"error": "title and content required"}), 400

    conn = get_db()
    # 参数化，防 SQLi；内容原样入库，XSS 在读取时由 escape() 统一转义
    conn.execute(
        "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, user_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "created"}), 201


if __name__ == "__main__":
    # debug=False：生产环境开启 debug 会暴露 Werkzeug 调试器，属高危配置
    app.run(debug=False, port=5000)
