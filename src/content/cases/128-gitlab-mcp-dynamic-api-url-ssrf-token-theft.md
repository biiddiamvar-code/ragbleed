---
caseId: "128"
title: "gitlab-mcp's dynamic-API-URL header let any caller redirect the server's own GitLab token to their host"
filed: "2026-09-21"
filedDisplay: "21 Sep 2026"
firstObserved: "15 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "@zereight/mcp-gitlab (npm, a.k.a. gitlab-mcp; versions < 2.1.27), Streamable HTTP and SSE transports with ENABLE_DYNAMIC_API_URL=true"
cve: "CVE-2026-61559 (GHSA-2h44-8472-frjj)"
readTime: "4 min read"
related: ["015", "055", "129"]
---

## Summary

gitlab-mcp is the most-downloaded community Model Context Protocol server for GitLab, giving coding agents like Claude, Cursor, and Copilot tool access to repositories, issues, pipelines, and wikis through a configured Personal Access Token (PAT). An opt-in setting meant for self-hosted, multi-tenant deployments let any caller who reached the HTTP transport supply a request header that redirected the server's own outbound API calls — token attached — to a host of their choosing. The server never checked whether the redirected destination was one it should trust with a credential; it only checked whether the header parsed as a URL.

## What was observed

The feature exists for operators running self-hosted GitLab instances at non-standard URLs: setting `ENABLE_DYNAMIC_API_URL=true` lets a caller's `X-GitLab-API-URL` header override the base URL the server uses for that request's GitLab API calls, rather than hardcoding one at startup. The validation applied to that header was a single line — `new URL(dynamicApiUrl)` — which confirms the value is syntactically a URL and nothing else. No allowlist, no hostname check, no distinction between the operator's own GitLab instance and an arbitrary attacker-controlled listener.

```
# illustrative: what the header check actually verified
dynamic_url = request.headers["x-gitlab-api-url"]
new URL(dynamic_url)              # throws only on malformed syntax
api_base = normalize(dynamic_url) # any reachable host accepted, no allowlist
# api_base then receives every outbound call for this request,
# each one carrying: Private-Token: <server's configured PAT>
```

The redirected value flowed through the server's request-building path into the function that attaches authentication to outbound fetches, which had no way to know the destination had been swapped out from under it. It attached the configured PAT to the request exactly as it would for a legitimate call to the real GitLab API — only now that request, credential included, went to whatever host the header named. An attacker needed no prior knowledge of the token: sending any ordinary tool call with the header pointed at a listener they controlled was sufficient. The next outbound call the server made delivered the PAT to that listener directly, over a channel the attacker owned from the start. From there the token grants its owner's full GitLab access — every repository the PAT can reach, CI/CD variables and secrets, and the ability to push code or rewrite pipelines if the token carries write scope.

## Mitigation

Upgrade to gitlab-mcp 2.1.27 or later, which checks the `X-GitLab-API-URL` hostname against an operator-supplied allowlist (`GITLAB_ALLOWED_HOSTS`) before using it, rather than accepting anything that parses as a URL. If you don't need multi-tenant routing, leave `ENABLE_DYNAMIC_API_URL` unset — the feature is opt-in for a reason, and the default configuration was never affected. If you do need it, set the allowlist to the exact hostnames you trust, and treat the previously configured PAT as compromised if the server was ever reachable with this flag on: rotate it and reissue one scoped to the minimum access the integration actually needs. This is rated medium rather than GitLab's CVSS 9.6 "Critical": the flag is off by default and documented as a self-hosted, multi-tenant feature, which meaningfully narrows how many real deployments were exposed — but where it was enabled, the outcome was a complete, unauthenticated credential handoff, which is why it isn't rated lower still. A header that changes where a credential gets sent needs the same scrutiny as a header that changes what gets read — validating that a string is a URL answers a different question than validating that it's safe to trust with a secret.
