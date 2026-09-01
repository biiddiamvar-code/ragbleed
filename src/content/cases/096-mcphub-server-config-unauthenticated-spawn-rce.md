---
caseId: "096"
title: "MCPHub's server-config endpoints spawned attacker-supplied commands from any authenticated account"
filed: "2026-09-01"
filedDisplay: "01 Sep 2026"
firstObserved: "31 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "MCPHub (samanhappy/mcphub), server-registration endpoints (versions before 0.12.15); companion authorization flaws in the same disclosure batch fixed across 1.0.29–1.0.32"
cve: "CVE-2026-79748 (CWE-862, CVSS 9.9), disclosed alongside CVE-2026-79744 through CVE-2026-79750 in the same MCPHub audit"
readTime: "5 min read"
related: ["042", "028", "017"]
---

## Summary

MCPHub is a hub that centrally manages and routes calls to multiple MCP servers behind a single set of HTTP endpoints. Its endpoints for creating and updating an MCP server's configuration accepted a `command` field and, for stdio-transport servers, immediately spawned that command as a subprocess of the MCPHub host process. The endpoints required a login but never checked whether the logged-in account held admin privileges, and nothing sanitized or allowlisted the command being spawned. Any authenticated non-admin user could register a server configuration naming a shell as its command and get it executed with the privileges of the MCPHub process — commonly root in the published Docker image. The bug was one of a batch of authorization flaws (CVE-2026-79744 through CVE-2026-79750) disclosed against the same codebase on 31 August 2026.

## What was observed

`POST /api/servers` and `PUT /api/servers/:name` create or update an MCP server entry and, for a stdio-transport server, spawn the configured process via `child_process.spawn` so MCPHub can talk to it. The route was reachable by any authenticated user; the handler never checked `req.user.isAdmin`, and neither `command` nor `args` was validated against an allowlist:

```
# authenticated as any ordinary (non-admin) MCPHub account
POST /api/servers
{ "name": "innocuous-server",
  "type": "stdio",
  "command": "/bin/sh",
  "args": ["-c", "id; whoami"] }
# -> MCPHub spawns the process immediately to establish the stdio connection,
#    running the attacker's command as the MCPHub server's own OS user
```

The same audit surfaced a cluster of related authorization gaps in the surrounding code: `PUT /api/system-config` let any authenticated user rewrite system configuration because the handler checked only that a session existed, not that it belonged to an admin (CVE-2026-79744); a bearer key scoped to one MCP server in a group granted access to every other server in that group because the group-route check verified only that some server in the group matched, then never re-checked the specific server being called (CVE-2026-79746); and the server-registration path itself, once authenticated, let a non-admin register a server pointing at an arbitrary URL and made the hub issue outbound requests to it with no loopback, RFC1918, or link-local (169.254.0.0/16) filtering, producing a fully reflected SSRF through the OpenAPI proxy path (CVE-2026-79747). Individually each bug is a missing or incomplete authorization check; together they show a codebase that repeatedly treated "logged in" as equivalent to "authorized to do this," a distinction that had to be re-derived and re-fixed at each endpoint rather than enforced once, centrally.

## Mitigation

Upgrade to MCPHub 1.0.32 or later, which cumulatively addresses the full batch; the RCE-causing gap itself was closed earlier, in 0.12.15, so deployments should confirm they are past that line at minimum and past 1.0.32 to close the rest. Where immediate upgrade isn't possible, restrict `/api/servers`, `/api/servers/:name`, and `/api/system-config` to admin sessions at a reverse proxy, and don't run the MCPHub container as root. The pattern worth generalizing: any endpoint that can cause a server-orchestration tool to execute a command or fetch a URL is a privileged endpoint by definition, regardless of what the route's name suggests about its purpose, and needs the same role check as the interface meant to be the "real" admin path.
