# secure-api —— 安全 REST API（作业第一部分）

基于 Flask 的安全 REST API，落实并演示三类安全防护：

| 防护点 | 技术手段 |
| --- | --- |
| 认证安全 | bcrypt 密码哈希 + JWT 无状态鉴权 |
| SQL 注入防护 | 全程参数化查询（`?` 占位符），无任何字符串拼接 |
| 存储型 XSS 防护 | 内容原样入库，渲染时由 Jinja2 自动转义 |

## 技术栈

- Python 3.10 / 3.11（本机以 3.10.12 实测通过，Flask 3.x 要求 ≥3.8）
- Flask 3.0.3
- flask-jwt-extended 4.6.0（JWT）
- bcrypt 4.1.3（密码哈希，cost=12）
- SQLite（Python 标准库 `sqlite3`，不引入 ORM）

## 目录结构

```
secure-api/
├── app.py                 # 主程序：注册/登录/鉴权/文章接口
├── init_db.py             # 初始化数据库 + 内置测试用户 alice
├── test_app.py            # pytest 自动化测试（9 个用例）
├── requirements.txt
├── .gitignore
└── .github/workflows/
    └── ci.yml             # CI/CD 流水线（测试 + SAST + 依赖审计）
```

## 快速开始

```bash
cd secure-api
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt pytest
python init_db.py                  # 建库并写入测试用户 alice / Alice#2026!
python app.py                      # 启动于 http://127.0.0.1:5000
```

> 注意：若 `python3 -m venv` 报 `ensurepip is not available`，先安装
> `sudo apt install python3.10-venv`（或对应 Python 版本的 `python3.x-venv`）。

## 接口清单与安全演示

以下命令均在服务启动后用 `curl` 验证（`📸` 为建议截图点）。

### 1) 注册 —— `POST /register`

```bash
curl -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"Bob#1234!"}'
# -> 201 {"msg":"注册成功"}
```

密码以 **bcrypt cost=12** 哈希后落库，数据库里看不到明文（`📸` 截图
`sqlite3 app.db 'SELECT username, password_hash FROM users;'`，可见 `$2b$12$...` 哈希串）。

### 2) 登录 —— `POST /login`（签发 JWT）

```bash
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice#2026!"}'
# -> 200 {"access_token":"eyJhbGciOiJIUzI1NiIs...","username":"alice"}
```

### 3) 受保护接口 —— `GET /me`

不带 token 返回 `401`，带 token 返回当前用户（`📸` 对比两张截图）：

```bash
curl -i http://127.0.0.1:5000/me                                  # 401 未授权
curl -H "Authorization: Bearer <上一步的token>" http://127.0.0.1:5000/me   # 200 {"id":1,"username":"alice"}
```

### 4) 存储型 XSS —— `POST /posts` + `GET /posts`

```bash
# 发布一段“恶意”内容（token 同上）
curl -X POST http://127.0.0.1:5000/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"title":"恶意文章","content":"<script>alert(1)</script>"}'
# -> 201 {"msg":"发布成功"}

# 浏览器打开列表页，脚本被转义为纯文本，不会弹窗
curl http://127.0.0.1:5000/posts
# -> <p>&lt;script&gt;alert(1)&lt;/script&gt;</p>
```

（`📸` 截图列表页 HTML 源码，标注 `<script>` 已被转义为 `&lt;script&gt;`。）

## 安全设计说明

- **bcrypt 哈希**：`bcrypt.hashpw(..., gensalt(rounds=12))`，自带盐值，`cost=12` 提高暴力破解成本；校验用 `checkpw`，失败与“用户不存在”返回同一句话，避免用户名枚举。
- **参数化查询**：所有 SQL 一律 `?` 占位符，例如登录处
  `SELECT ... WHERE username = ?`。若写成 `f"... WHERE username = '{username}'"`，
  `' OR '1'='1` 即可绕过登录（`test_login_sql_injection_blocked` 用例验证了这一点被拦截）。
- **Jinja2 自动转义**：`render_template_string` 默认开启转义，`{{ post['content'] }}` 会把
  `<`、`>`、`'` 等输出成 HTML 实体，存储型 XSS 在渲染层被阻断。
- **其它**：JWT 密钥从环境变量 `JWT_SECRET_KEY` 读取（默认值仅本地开发用，且 ≥32 字节）；
  `app.run(debug=False)`（生产开启 debug 会暴露 Werkzeug 调试器）；统一错误信息防止枚举。

## 自动化测试

```bash
pip install pytest
pytest -v          # 9 个用例全通过
```

覆盖：注册成功/重名、登录成功/密码错误、**SQLi 绕过被拦**、无 token 401、
带 token 200、未登录发帖 401、**XSS 内容被转义**。

## CI/CD

`.github/workflows/ci.yml` 在 push/PR 时自动执行两个 Job：

1. **test**：Python 3.10 / 3.11 矩阵，装依赖 → `init_db.py` → `pytest -v`。
2. **security**：`bandit`（SAST 静态扫描）+ `pip-audit`（依赖漏洞审计）。

推送到 GitHub 后，在仓库 **Actions** 页可看到流水线绿灯（`📸` 截图）。

## 📸 截图清单（写入实验报告）

1. `python init_db.py` 输出 + `sqlite3` 查看 `password_hash` 为 bcrypt 哈希串。
2. 注册 / 登录成功返回（登录含 JWT）。
3. 无 token 访问 `/me` 返回 401、带 token 返回 200 的对比。
4. 发布含 `<script>` 的文章后，`GET /posts` 源码里脚本被转义为 `&lt;script&gt;`。
5. 使用 `' OR '1'='1` 尝试登录返回 401（SQLi 被拦）。
6. `pytest -v` 全绿截图。
7. GitHub Actions 流水线（test + security）通过截图。
