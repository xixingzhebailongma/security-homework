# Security Homework

课程作业，包含两部分 + 控制问题附录。

## 1. [secure-api](./secure-api) —— Flask 安全 REST API + CI/CD

- bcrypt 密码哈希（cost=12）+ JWT 无状态鉴权
- SQL 注入防护（全程 `?` 参数化查询）
- 存储型 XSS 防护（`markupsafe.escape()` 输出转义）
- GitHub Actions CI/CD（pytest + bandit SAST + pip-audit SCA）

## 2. [cve-2024-23334](./cve-2024-23334) —— aiohttp 路径穿越漏洞复现与修复

- 漏洞原理（源码级分析：`follow_symlinks=True` 缺失根目录包含性校验）
- Vulhub 等价复现环境（docker-compose + Dockerfile）
- PoC 与修复验证（aiohttp 3.9.1 → 3.9.2）
- 修复文件：[cve-2024-23334/fixes/](./cve-2024-23334/fixes/)

## 附录

- 控制问题答辩：[控制问题.md](./控制问题.md)

## 关键链接

- 仓库：https://github.com/xixingzhebailongma/security-homework
- 最近一次成功流水线（Bandit + pip-audit 全绿）：
  https://github.com/xixingzhebailongma/security-homework/actions/runs/41054593477

各子目录内含独立的 `README.md` 与可运行代码，操作步骤详见对应说明。
