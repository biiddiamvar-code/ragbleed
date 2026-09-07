---
caseId: "109"
title: "n8n's public MCP client-registration endpoint let anyone fill the database and take the instance down"
filed: "2026-09-07"
filedDisplay: "07 Sep 2026"
firstObserved: "26 Apr 2026"
severity: high
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "n8n workflow automation platform, MCP OAuth Dynamic Client Registration endpoint (< 1.123.32; < 2.17.4; < 2.18.1)"
cve: "CVE-2026-42236 (\"OverDoS\", GHSA-49m9-pgww-9vq6)"
readTime: "5 min read"
related: ["009", "050", "077"]
---

## Summary

n8n exposes an OAuth Dynamic Client Registration (DCR) endpoint as part of its Model Context Protocol (MCP) integration, letting MCP clients register themselves against an n8n instance without prior administrator provisioning. Checkmarx Zero researchers found that endpoint accepted unauthenticated registration requests and persisted each one to the instance's database with no meaningful ceiling on how many could accumulate, letting a remote, unauthenticated attacker fill the database and render the instance unresponsive. Disclosed as "OverDoS," the flaw affected every internet-facing n8n instance by default — a single Shodan query returned more than 70,000 candidates — regardless of whether the operator had the MCP feature itself turned on.

## What was observed

Dynamic Client Registration, defined in RFC 7591, lets an OAuth client register itself at runtime by POSTing a JSON description of itself — `redirect_uris`, `client_name`, `grant_types` — to a public endpoint, skipping the usual out-of-band provisioning step. n8n implements a DCR endpoint as part of its MCP feature, and that endpoint stayed reachable, anonymous, and writable on every default install independent of the separate toggle operators use to enable or disable MCP: that toggle blocked *using* an MCP connection, not *registering* one.

```
# illustrative — no auth guard on the registration path
POST /mcp-oauth/register     # skipAuth: true
{ "client_name": "...", "redirect_uris": [...] }
-> INSERT INTO oauth_clients (...)   # persists regardless of whether MCP is enabled
```

The only friction between an attacker and unbounded database growth was a 16 MB default request-body cap (`N8N_PAYLOAD_SIZE_MAX`) and a per-IP rate limit of ten requests every five minutes — roughly 160 MB of attacker-controlled data per IP every five minutes, and neither limit accounts for an attacker rotating IPs or using distributed infrastructure. Disk and memory were the only real ceiling on how much an unauthenticated caller could write into the instance's database; once full, the instance stopped serving legitimate requests. A related, lower-severity flaw in the same registration flow (CVE-2026-42230) let the attacker-supplied `redirect_uri` also fire on a *denied* consent request, and let attacker-supplied client names spoof a recognized integration's icon in the consent dialog — turning the same endpoint into a phishing surface alongside the denial-of-service one.

> The registration endpoint ships exposed, anonymous, and writable on a fresh install — the bug requires no misconfiguration to trigger.

## Mitigation

Upgrade to n8n 1.123.32, 2.17.4, or 2.18.1 or later, which cap the number of registered clients and stop accepting new registrations once MCP is disabled on the instance. Cloud-hosted n8n instances were patched automatically. Where upgrading isn't immediate, restrict network access to the instance — VPN, SSO-gated reverse proxy, or IP allowlist — since no in-application setting mitigates the exposure. The pattern generalizes past n8n: any self-service OAuth or MCP registration endpoint that persists caller-supplied data before establishing trust needs its own resource ceiling, independent of whatever feature flag operators believe is gating it — the same class of unauthenticated MCP exposure this database has already logged against this platform in cases 009, 050, and 077.
