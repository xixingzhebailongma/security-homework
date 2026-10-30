# Security Homework

课程作业，包含两个部分：

## 1. [secure-api](./secure-api) —— Flask 安全 REST API + CI/CD

- bcrypt 密码哈希（cost=12）+ JWT 无状态鉴权
- SQL 注入防护（全程参数化查询）
- 存储型 XSS 防护（Jinja2 模板自动转义）
- GitHub Actions CI/CD（pytest 测试矩阵 + bandit SAST + pip-audit 依赖审计）

## 2. [cve-2024-23334](./cve-2024-23334) —— aiohttp 路径穿越漏洞复现与修复

- 漏洞原理（源码级分析：`follow_symlinks=True` 缺失越界校验）
- Vulhub 复现环境（docker-compose + Dockerfile）
- PoC 与修复验证（aiohttp 3.9.1 → 3.9.2）

各子目录内含独立的 `README.md` 与可运行代码，操作步骤详见对应说明。
