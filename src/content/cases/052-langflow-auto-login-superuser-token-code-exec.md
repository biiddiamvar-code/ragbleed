---
caseId: "052"
title: "Langflow's auto-login endpoint minted superuser tokens for anyone, and a code-validation endpoint ran them as Python"
filed: "2026-08-06"
filedDisplay: "06 Aug 2026"
firstObserved: "17 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Langflow OSS (1.0.0 through 1.10.0)"
cve: "CVE-2026-9198"
readTime: "4 min read"
related: ["040", "045", "042"]
---

## Summary

Langflow OSS shipped an unauthenticated endpoint that handed out valid superuser credentials to any caller, and a separate endpoint that ran arbitrary Python on whatever text it was given. Chained together, the two produced full remote code execution against a default installation with no authentication step required at all. IBM patched both endpoints in Langflow 1.10.1 on 17 July 2026; CISA added the flaw to its Known Exploited Vulnerabilities catalog on 4 August 2026 after observing active exploitation of instances that had not updated.

## What was observed

The `/api/v1/auto_login` endpoint exists so a freshly installed Langflow instance can issue itself a working session before any administrator account has been created. In versions 1.0.0 through 1.10.0, the endpoint answered any network request with a valid SUPERUSER bearer token, with no check for whether setup had already completed or whether the caller had presented any credential. Separately, the `/api/v1/validate/code` endpoint — built so the visual flow editor could sanity-check a Python snippet before wiring it into a node — passed the submitted text directly to Python's `exec()`.

Neither endpoint was dangerous on its own within Langflow's intended deployment model, where `auto_login` is meant to be reachable only during the brief pre-setup window. Chaining them removed that assumption entirely:

```
# unauthenticated: POST /api/v1/auto_login  -> returns SUPERUSER bearer token
# with that token:  POST /api/v1/validate/code
#   -> request body passed straight to Python's exec() on the server
```

A request for a token followed by a request to `validate/code` carrying that token executed arbitrary code under the Langflow service account, with no prior authentication step and no user interaction. The CVSS score of 9.8 reflects exactly that profile — no credentials, no interaction, default configuration — the same profile that put Langflow's file-upload path traversal (case 045) and cross-tenant IDOR flow execution (case 040) on this site's list of default-config failures earlier this year. Three Langflow RCE and access-control bugs landing within a single year is less a story about one bad endpoint than about a codebase whose bootstrap and validation paths keep assuming a trust boundary that the network doesn't actually enforce.

## Mitigation

Upgrade to Langflow 1.10.1 or later, which closes both the token-issuance and code-execution paths. Given CISA's Known Exploited Vulnerabilities deadline of 7 August 2026 for federal instances, and confirmed in-the-wild exploitation, treat this as an emergency patch rather than routine maintenance for any internet-reachable Langflow deployment. The broader lesson: an endpoint scoped to a pre-setup bootstrap window has to verify that the window is still open — checking whether authentication has already been configured, not just trusting that the endpoint won't be called after setup — because an endpoint that answers identically before and after setup isn't a bootstrap mechanism, it's an open door with a description attached.
