---
caseId: "045"
title: "Langflow's file-upload endpoint let a crafted filename write files anywhere the process could reach"
filed: "2026-08-03"
filedDisplay: "03 Aug 2026"
firstObserved: "27 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Langflow (<= 1.8.4; fixed in 1.9.0)"
cve: "CVE-2026-5027"
readTime: "5 min read"
related: ["040", "002", "018"]
---

## Summary

Langflow's `POST /api/v2/files` endpoint took the filename out of a multipart upload and handed it straight to the filesystem without stripping directory-traversal sequences. A filename containing repeated `../` segments walked the write destination out of the intended upload folder and let an attacker place a file anywhere the Langflow process had write access — including `/etc/crontab`, where a single line turns into a root shell within about a minute. Because Langflow enables unauthenticated auto-login by default, an attacker needed no credentials at all: a request to `/api/v1/auto_login` handed back a valid session token, and that token was all `/api/v2/files` required. This is a separate defect from the `/api/v1/responses` cross-tenant IDOR covered in case 040; the two share a product, not a root cause.

## What was observed

The upload handler resolved the destination path by joining the storage directory with the filename field from the request, and never called anything equivalent to path canonicalization or a same-directory check before writing:

```
# file_path = folder_path / file_name
# '../' sequences in file_name are never stripped or rejected,
# so the write lands wherever the traversal points
```

Combined with default auto-login, the exploit chain required only two requests: one to `/api/v1/auto_login` for a token, and one multipart upload to `/api/v2/files` with a filename built from nine or more `../` segments followed by the target path. Public proof-of-concept code used this to write a cron entry that fired a reverse shell, since system cron executes `/etc/crontab` as root regardless of which unprivileged account the Langflow process itself was running under — turning an arbitrary-file-write primitive into full root compromise without needing a second, separate escalation bug. The same primitive supports dropping an SSH `authorized_keys` file or a web shell instead; blocking the crontab route specifically would not have closed the underlying flaw. VulnCheck and others observed active scanning and exploitation attempts against internet-facing Langflow instances following public disclosure.

## Mitigation

Upgrade to Langflow 1.9.0 or later, which sanitizes the filename parameter and constrains writes to the intended storage directory. Where upgrading isn't immediate, set `LANGFLOW_AUTO_LOGIN=false` to remove the credential-free path into the vulnerable endpoint, restrict network access to Langflow so it isn't reachable from untrusted networks, and run the process as a non-root, least-privilege user so an arbitrary file write can't reach root-owned locations like `/etc/crontab` even if the traversal itself isn't blocked. Filename-based path traversal is one of the oldest bug classes in web applications; its recurrence here is a reminder that low-code AI orchestration platforms inherit ordinary web-application attack surface — file uploads, authentication defaults, path handling — in addition to whatever risk their AI-specific features add, and each needs the same scrutiny it would get in any other web app.
