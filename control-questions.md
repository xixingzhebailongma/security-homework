# Control Questions (Oral Exam Prep / Report Appendix)

## 1. Why is bcrypt preferable to SHA-256 for password hashing?

SHA-256 is a *fast* hash: GPUs can try billions of guesses per second, so it is good for integrity
checks but unsuitable for storing passwords. bcrypt is a *deliberately slow, tunable-cost password
hash*: it embeds a salt and, via the `cost` parameter (12 in this work), multiplies the per-hash
computation time, dramatically raising the cost of offline brute force. Verification recomputes and
compares with `checkpw`; the database stores only the hash, never the plaintext.

## 2. Main difference between SAST and DAST?

- **SAST** (static analysis, e.g. Bandit): analyzes source/bytecode without running it, pinpoints
  exact line numbers, and covers all code paths — but can produce false positives.
- **DAST** (dynamic analysis, e.g. Burp): sends real requests to the *running* application from the
  outside; fewer false positives and closer to real attacks, but coverage is limited to actually
  reachable paths and entry points.

They complement each other: SAST finds issues early with broad coverage; DAST verifies real
exploitability.

## 3. How does a JWT work? What does it contain, and how does the server verify it?

A JWT is three Base64URL segments — `Header.Payload.Signature`. The server signs the first two
segments with a secret using HMAC (or RSA). To verify, it recomputes the signature and compares it
to the third segment, while also checking claims such as `exp` (expiry). The **payload is only
Base64-encoded, not encrypted** — anyone can decode it, so it must not carry sensitive data;
security relies on the signature preventing tampering.

## 4. Risks of not auditing third-party dependencies?

Known CVEs in third-party libraries (e.g. Log4Shell) become part of your own attack surface — by
merely referencing a vulnerable library, you inherit its vulnerability. **SCA (e.g. pip-audit)**
checks dependencies against PyPI/OSV before they reach production. In this work, `pip-audit` did
catch a real issue: it flagged Flask 3.0.3 (CVE-2026-27205), prompting the upgrade to 3.1.3.

## 5. Advantages of Docker/Vulhub for studying cybersecurity?

Isolation, reproducibility, one-command teardown/rebuild; no pollution of the host machine; and the
dependency version can be pinned to the exact vulnerable commit, keeping the reproduction stable
and reproducible.

## 6. Difference between a vulnerability and an exploit; what did you reproduce?

- A **vulnerability** is the defect itself (aiohttp's missing path-containment check in the
  `follow_symlinks=True` branch).
- An **exploit** is the specific input/request that triggers it (a GET request with `../` segments).

This work reproduced the **exploit** and analyzed the **vulnerability**.

## 7. Why is regression testing critical after applying a fix?

A fix can introduce functional regressions or new edge cases (e.g. a check that is too strict and
rejects legitimate requests). Proving "the attack fails" is not enough — you must also prove
"normal functionality still works". That is why the fix verification confirms the normal static
file still returns 200 alongside the attack returning 404.

## 8. How does reproducing known CVEs help a security professional?

Pentesters need to know how a real vulnerability is exploited to assess risk accurately; SOC/blue
team analysts need to understand the exploit traffic's characteristics to write detection rules.
Reproduction is the most direct way to turn an abstract CVE description into actionable knowledge.
