---
caseId: "201"
title: "Dify shipped its code-execution sandbox with a public default API key, dify-sandbox"
filed: "2026-11-08"
filedDisplay: "08 Nov 2026"
firstObserved: "14 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Dify 1.0 through 1.18.0 and 2.0.0-beta.0 to beta.2 (per CVE record); advisory confirmed on v1.15.0 with langgenius/dify-sandbox 0.2.15"
cve: "CVE-2026-123135 (CWE-259 / CWE-798; CVSS 3.1 6.3; tracked in langgenius/dify issue #44054)"
readTime: "3 min read"
related: ["144", "047", "006"]
---

## Summary

Dify's Docker deployment files and API configuration carried a fixed default key, `dify-sandbox`, for authenticating to the code-execution sandbox. The key matches the project name and is publicly documented in the repository. Where the sandbox endpoint is reachable, any caller can submit code to it. A fix pull request existed on 08 Nov 2026 but had not been merged, so no patched release is confirmed.

## What was observed

A third-party advisory published 14 Oct 2026 reports that the sandbox container checks an `X-Api-Key` header against the default value `dify-sandbox`. Authentication is enforced, since a wrong key returns HTTP 401; the weakness is that the expected value is public. The advisory lists four locations for the default: the `CODE_EXECUTION_API_KEY` default in `api/configs/feature/__init__.py`, the fallback in `docker/docker-compose.yaml`, active (not commented) entries in `docker/.env.example`, and the bind-mounted sandbox `config.yaml`. A standard `cp .env.example .env` therefore kept the key.

Reachability depended on the deployment. In the default Compose file the advisory found no published sandbox port, so only the internal Docker network could reach it. In `docker-compose.middleware.yaml`, the advisory states that the Squid proxy publishes host port 8194 and forwards requests to `/v1/sandbox/run`. With the default key, a remote caller could run Python or JavaScript in the sandbox container, which the advisory reports has outbound network access. Attempts to move laterally to the Redis and Postgres containers failed on name resolution.

The advisory is a single researcher's report and its claims were not independently reproduced here. The CVE record scores the issue at CVSS 3.1 6.3. The mechanism is rated medium: code execution is confined to the sandbox container, and exposure requires the middleware deployment or another published endpoint.

## Mitigation

Set `SANDBOX_API_KEY` to a unique random value in every deployment and remove the `dify-sandbox` default from local `.env` files. Do not publish port 8194 or the sandbox endpoint beyond the host. Pull request #44192 would require the key, reject the legacy value at sandbox start and unpublish the port by default; it was open at the time of filing, so check the Dify release notes for the version that includes it.

A shipped example value is a deployed credential. A configuration that starts without the operator choosing a secret should refuse to start.
