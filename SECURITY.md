# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** This project
handles threat-intelligence data and runs an LLM pipeline; a public report
could expose users before a fix exists.

Report privately through GitHub's **Security → Report a vulnerability**
("Private vulnerability reporting") on this repository, or by email to
**sandro.rossetti.study@gmail.com** with `[SECURITY]` in the subject.

Please include: what you found, how to reproduce it, the affected version or
commit, and the impact you foresee. You will get an acknowledgement within a
few days. Coordinated disclosure is appreciated — give a reasonable window for
a fix before any public write-up.

## Scope worth flagging

- Secrets or credentials committed anywhere in history.
- The TLP boundary: any path by which content above `PEST_AI_TLP_CLOUD_MAX`
  could reach a third-party LLM without an audited override.
- SSRF via webhooks or feed URLs; injection via ingested article content.
- Authentication or CSRF bypass on the web UI / API.

## Supported versions

This is pre-1.0 software; only the latest `main` receives fixes.
