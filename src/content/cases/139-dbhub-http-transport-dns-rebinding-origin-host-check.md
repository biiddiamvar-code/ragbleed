---
caseId: "139"
title: "DBHub's DNS-rebinding guard compared the Origin header to the Host header, and a rebound domain matched both"
filed: "2026-09-27"
filedDisplay: "27 Sep 2026"
firstObserved: "24 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "DBHub (npm @bytebase/dbhub, all versions < 0.22.5) when run with the HTTP transport (--transport http); default stdio mode not affected"
cve: "CVE-2026-61742 (GHSA-fm8p-53ww-hf6w)"
readTime: "4 min read"
related: ["133", "087", "086"]
---

## Summary

DBHub is an MCP server that gives LLM agents SQL access to PostgreSQL, MySQL, SQL Server, Oracle, MariaDB, and SQLite. In HTTP transport mode, its `/mcp` endpoint required no authentication and relied on a single browser-origin check that compared the request's `Origin` hostname against its `Host` hostname. A DNS-rebinding attack produced a request in which both headers named the same attacker domain, so the check passed and any web page the operator visited could invoke DBHub's SQL tools. Fixed in 0.22.5.

## What was observed

The advisory, first published 24 Sep 2026, described the check in the HTTP server. When a request carried an `Origin` header, DBHub parsed the origin's hostname, stripped the port from `Host`, and returned 403 only if the two differed. When they matched, the server reflected the caller's `Origin` into `Access-Control-Allow-Origin` and continued to dispatch the MCP call.

```
// server, illustrative
if (originHostname !== hostHeaderHostname) return 403;   // relative comparison only
res.header("Access-Control-Allow-Origin", origin);       // reflected back to the caller
// -> JSON-RPC tools/call dispatched to execute_sql
```

That comparison stopped an ordinary cross-origin request, where a page on `evil.example` sends `Origin: evil.example` to `Host: localhost:8080`. It did not stop rebinding. The attacker served a script from a low-TTL hostname, then re-pointed that hostname at the address where DBHub listened. The browser still considered the page same-origin with itself and sent both `Origin` and `Host` with the attacker's hostname. The two strings were equal, DBHub accepted the request, and the reflected CORS header let the script read the response.

Neither header was ever checked against a fixed list of names the server should answer to. Both values came from the attacker's domain, so comparing them to each other proved nothing.

The advisory noted that no prompt injection or model involvement was required: the page called the MCP tools directly and deterministically. With DBHub's default demo configuration, that meant read and write access to the bundled SQLite database. With a real data source, the attacker got whatever the configured database credentials and DBHub's tool permissions allowed. Enumeration and reads were always possible, and writes depended on that configuration. The advisory's recommended severity was High, rising to Critical when the HTTP transport fronted production or broadly privileged credentials; the published CVSS 3.1 score was 9.8.

We rated this high. The HTTP transport is opt-in, but it is a documented deployment mode. Once enabled, a single visit to a hostile page turned the operator's browser into an unauthenticated SQL client for every database DBHub was connected to.

## Mitigation

Upgrade to DBHub 0.22.5 or later (fix commit 5bf5c32, pull request #340). Where the HTTP transport is not needed, use stdio. Where it is needed, keep DBHub bound to loopback, place it behind a reverse proxy that enforces authentication and a fixed `Host` allowlist, and connect it with a database role limited to the schemas and privileges the agent actually needs.

The broader lesson extends beyond DBHub. A DNS-rebinding defense has to compare `Host` against a fixed allowlist the server controls. Comparing one attacker-influenced header with another does not protect anything.
