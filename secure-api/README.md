# secure-api — Secure REST API (Part 1)

A Flask-based secure REST API with three endpoints and three security controls:

| Control | Implementation |
| --- | --- |
| Authentication (1 pt) | bcrypt password hashing (cost=12) + stateless JWT |
| SQL injection (0.5 pt) | parameterized queries (`?` placeholders) everywhere, no string concatenation |
| Stored XSS (0.5 pt) | `markupsafe.escape()` HTML-encodes user data on output |

## Stack

- Python 3.10 / 3.11
- Flask 3.1.3
- flask-jwt-extended 4.6.0 (JWT)
- bcrypt 4.1.3 (password hashing, cost=12)
- SQLite (stdlib `sqlite3`)

## Structure

```
secure-api/
├── app.py                 # /auth/login, /api/data, /api/posts
├── init_db.py             # creates the DB + test user alice / Alice#2026!
├── test_app.py            # pytest suite (8 tests)
├── requirements.txt
├── .gitignore
└── .github/workflows/
    └── ci.yml             # CI/CD pipeline (tests + SAST + SCA)
```

## Quick Start

```bash
cd secure-api
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt pytest
python init_db.py                  # create DB and test user alice / Alice#2026!
python app.py                      # http://localhost:5000
```

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| POST | `/auth/login` | Login: bcrypt check, issues a JWT on success |
| GET | `/api/data` | JWT-protected: current user's posts (title/content escaped) |
| POST | `/api/posts` | JWT-protected: create a post (parameterized query) |

## Manual Tests (for the report)

```bash
# 1. /api/data without a token → 401
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/api/data

# 2. login to get a token
TOKEN=$(curl -s -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice#2026!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 3. /api/data with a token → 200 + empty list
curl -s http://localhost:5000/api/data -H "Authorization: Bearer $TOKEN"

# 4. create a post carrying an XSS payload
curl -s -X POST http://localhost:5000/api/posts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"<script>alert(1)</script>","content":"xss test"}'

# 5. read again → title is escaped as &lt;script&gt;
curl -s http://localhost:5000/api/data -H "Authorization: Bearer $TOKEN"
```

## Security Design

- **Authentication**: passwords stored with `bcrypt.hashpw(..., gensalt(rounds=12))`; login uses
  `checkpw`, then `create_access_token`; `@jwt_required()` guards `/api/data` and `/api/posts`;
  token lifetime `JWT_ACCESS_TOKEN_EXPIRES = 900` (15 min).
- **SQLi protection**: all SQL uses `?` placeholders, e.g. login's `SELECT ... WHERE username = ?`.
  With `f"... WHERE username = '{username}'"`, `' OR '1'='1` would bypass login — the test
  `test_login_sql_injection_blocked` verifies this is blocked.
- **XSS protection**: content is stored raw and escaped on read by `markupsafe.escape()`, turning
  `<`, `>`, `&`, `'`, `"` into HTML entities.
- **Other**: unknown-user and wrong-password both return `invalid credentials` (no enumeration);
  the JWT secret comes from `JWT_SECRET_KEY` (default only for local dev); `app.run(debug=False)`.

## Automated Tests

```bash
pip install pytest
pytest -v          # 8 tests pass
```

Covers: login success / wrong password, **SQLi blocked**, no-token 401, with-token 200 empty list,
unauthenticated post 401, missing-fields 400, **XSS escaped**.

## CI/CD

`.github/workflows/ci.yml` (`Security CI`) runs two jobs on push / PR to `main`:

1. **test**: Python 3.11, install deps → `pytest -v` (8 tests).
2. **security**:
   - SAST: `bandit -r . -x ./.venv --severity-level medium` (medium+ fails CI)
   - SCA: `pip-audit -r requirements.txt` (checks deps against PyPI/OSV)

> `pip-audit` flagged `Flask 3.0.3` (CVE-2026-27205 / PYSEC-2026-2151, sensitive session-cache
> disclosure, fixed in 3.1.3); upgrading to `Flask==3.1.3` resolved it. Bandit reports 0 medium+.
