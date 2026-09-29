---
caseId: "145"
title: "Bifrost AI gateway accepted stdio MCP client registrations from unauthenticated callers under its default auth-off configuration, spawning the supplied command on registration"
filed: "2026-09-29"
filedDisplay: "29 Sep 2026"
firstObserved: "02 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Bifrost (maximhq/bifrost) HTTP gateway, transports/v2.0.0 and earlier with governance.auth_config.is_enabled=false (the shipped default); fixed in transports/v2.1.0"
cve: "CVE-2026-90898 (GHSA-gqjq-cgxr-8c7c)"
readTime: "4 min read"
related: ["096", "028", "141"]
---

## Summary

Bifrost is an LLM gateway that fronts model providers and also brokers MCP tool servers for the agents behind it. Its management API registered MCP clients, and a `stdio` client was defined as a command plus arguments that the gateway started as a subprocess the moment the client was added. Authentication on that API was off by default, and with it off every caller was treated as a local administrator. One unauthenticated `POST /api/mcp/client` therefore ran an arbitrary program as the gateway process user.

## What was observed

The CVE record, published 14 Sep 2026 with JFrog as the reporting party, stated the chain in three facts. Bifrost's default was `governance.auth_config.is_enabled=false`. With auth disabled, the request context marked every caller as an authenticated admin. The MCP client registration handler accepted `connection_type: "stdio"` and executed the supplied `command` and `args` immediately, with no MCP handshake required before the process started. On the official container image the process ran as `appuser`.

```
// Illustrative request against a default-configured gateway
POST /api/mcp/client            // no Authorization header
{ "name": "x", "connection_type": "stdio", "command": "<program>", "args": [...] }
// -> gateway exec()s <program> as the Bifrost process user
```

The fix, pull request #6757 (merged 02 Sep 2026, shipped in transports/v2.1.0), described a second primitive on the same endpoint. An `http` or `sse` client could be registered with a `connection_string` pointing at loopback, RFC1918, link-local or CGNAT addresses, which made the gateway issue requests to internal services, including the `169.254.169.254` cloud metadata endpoint. That SSRF path did not receive a separate CVE. The same pull request found that the TLS client builder returned `nil` when no TLS config was set, so MCP HTTP connections fell back to the upstream library's default client with no dial-time guard at all.

The gateway's position made the impact wider than the process. A Bifrost instance holds provider API keys for every model it routes to and sits on the network path between agents and their tools. Code execution in that process exposed those keys and the tool traffic. The record scored CVSS 3.1 9.8; we rated this high, the top of our scale, without divergence, because the vulnerable state was the default.

## Mitigation

Upgrade to transports/v2.1.0 or later. The patched handler refuses `stdio` registrations and private-network `http`/`sse` targets with HTTP 403 whenever the request arrived through the auth-bypassed path, and routes all MCP HTTP connections through a dial guard that blocks link-local and unspecified addresses regardless of auth state. Authenticated administrators retain both capabilities; operators can still declare stdio clients in `config.json`.

Upgrading alone leaves the management API open for every other operation. Enable `governance.auth_config`, bind the management port to a private interface, and rotate any provider keys held by a gateway that was reachable while running v2.0.0 or earlier with auth off.

An API that turns a JSON body into a spawned process is a shell endpoint, whatever its route is called.
