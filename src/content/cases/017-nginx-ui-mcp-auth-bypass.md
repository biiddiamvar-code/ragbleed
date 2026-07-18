---
caseId: "017"
title: "nginx-ui's MCP integration had two doors to the same room — only one of them was locked"
filed: "2026-04-20"
filedDisplay: "20 Apr 2026"
firstObserved: "30 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "nginx-ui (versions prior to 2.3.4; chainable with CVE-2026-27944 in versions prior to 2.3.3)"
cve: "CVE-2026-33032 (\"MCPwn\")"
readTime: "5 min read"
related: ["014", "015", "016"]
---

## Summary

When nginx-ui added MCP support so AI tools could manage nginx configuration through it, that support arrived as two HTTP endpoints wired to the same underlying handler. One of them checked authentication. The other — the one that actually executes configuration changes — only checked an IP allowlist, and that allowlist was empty by default, which meant it accepted every address rather than none.

## What was observed

The MCP integration exposes `/mcp` for session establishment and `/mcp_message` for invoking tools. Both routes lead to the same set of privileged operations: writing nginx configuration, triggering a reload, and other administrative actions. `/mcp` enforces both an IP allowlist and authentication middleware. `/mcp_message` — where the actual tool invocations happen — only ran the allowlist check, and an empty allowlist fails open rather than closed.

```
GET  /mcp          → IP allowlist + auth middleware   (locked)
POST /mcp_message   → IP allowlist only, default empty → fails open (unlocked)
```

An attacker with network access could skip straight to `/mcp_message` and invoke any of the twelve MCP tools it exposes — rewriting nginx config files with automatic reload included — without ever passing through the authenticated endpoint at all. A related, separately-patched flaw (CVE-2026-27944, an unauthenticated backup-download endpoint leaking the encryption keys needed to decrypt those backups) meant that even the one nominal barrier protecting session establishment — a `node_secret` value — could itself be extracted without credentials on older versions, collapsing the whole chain to zero prerequisites.

Because nginx commonly sits as a reverse proxy in front of production services, rewriting its configuration isn't a contained incident — it's a foothold in front of everything nginx routes to. Scans found roughly 2,600 publicly reachable instances, and multiple threat-intelligence groups confirmed active exploitation within about a month of the flaw becoming public.

## Mitigation

Upgrade to nginx-ui 2.3.4 or later, which closes the authentication gap on `/mcp_message` and addresses the chained backup-key exposure from 2.3.3. If immediate patching isn't possible, populate the IP allowlist explicitly — the default empty list is the failure mode here, not a missing feature — and disable MCP functionality entirely until upgraded if you can't restrict network access to trusted hosts. The broader lesson for anyone bolting MCP support onto an existing application: every endpoint the integration adds needs to inherit the full authentication stack the rest of the application already has, not a lighter version of it applied inconsistently across routes that reach the same privileged code.
