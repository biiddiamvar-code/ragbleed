---
caseId: "038"
title: "HashiCorp's Consul MCP server could hand one client's Consul token to another"
filed: "2026-07-30"
filedDisplay: "30 Jul 2026"
firstObserved: "29 Jul 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "consul-mcp-server (0.1.0 through 0.1.3)"
cve: "CVE-2026-16326 (cross-tenant credential reuse); CVE-2026-16328 (SSRF via client-supplied backend address)"
readTime: "4 min read"
related: ["016", "008", "031"]
---

## Summary

HashiCorp's consul-mcp-server gives AI agents and tooling access to a Consul cluster over MCP, authenticating to Consul with a token configured in the server's own environment and caching a per-session authenticated client. Two flaws, published together in HashiCorp's July 29 advisory, undermined that isolation from two directions: a per-request override let a connected client redirect the server's Consul API traffic — and its configured token — to an address of the client's choosing, and a session-isolation bug in the server's stateless transport mode let one client's authenticated Consul client get reused for a different client's requests. Both are fixed in 0.1.4.

## What was observed

consul-mcp-server supported a per-request override of the Consul backend address via a client-supplied HTTP header, intended to let a single server instance be pointed at different Consul endpoints. The override path did not validate or restrict the destination. A connected client could set that header to an attacker-controlled address and cause the server to send its next Consul API request — including whatever token was configured in the server's environment — to that destination instead of the real cluster. Deployments that ran without a Consul token configured were not exposed to credential exfiltration by this path, but any deployment relying on the server's own token to reach Consul was.

The second flaw sat in how the server handled concurrent clients when running in stateless transport mode, where the server does not persist a dedicated session per connection. To avoid re-authenticating to Consul on every call, the server kept a cache of already-authenticated Consul clients. In stateless mode, that cache was not correctly keyed per client, so a tool call from one connected client could execute using a different client's cached Consul session — meaning the token-scoped permissions of client A could act on behalf of a request that actually originated from client B. Deployments running in stateful mode, or with only one client ever connected, were not affected; the bug required more than one client sharing a stateless-mode server instance.

> The two issues compound each other in the worst case: an override that leaks a token to an attacker-controlled endpoint, and a session cache that hands a token to the wrong client even without any leak at all — two separate roads to the same outcome, tenant isolation failing at the credential layer.

Neither CVE carries a published CVSS score in the advisory. HashiCorp attributes CVE-2026-16328 to an external researcher and CVE-2026-16326 to an internal HashiCorp team, and states both were fixed before public disclosure.

## Mitigation

Upgrade to consul-mcp-server 0.1.4, which is unaffected by both issues. Where immediate upgrade isn't possible, restrict network access to the MCP server to trusted clients only, and avoid stateless-mode deployments that accept connections from more than one client. More broadly, this is the same failure mode this database has logged repeatedly for MCP servers acting as credentialed proxies (see case 016, case 008): a server that authenticates once to a backend on behalf of many callers has to treat per-client isolation as a security boundary, not an implementation detail of its caching layer — and any client-suppliable parameter that changes where the server sends its own credentials needs the same validation discipline as user-supplied URLs anywhere else in the stack (case 031).
