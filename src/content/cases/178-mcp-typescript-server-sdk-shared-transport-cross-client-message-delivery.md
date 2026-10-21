---
caseId: "178"
title: "MCP TypeScript server SDK matched responses to connections by JSON-RPC id alone, delivering one HTTP client's messages to another"
filed: "2026-10-21"
filedDisplay: "21 Oct 2026"
firstObserved: "15 Oct 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "@modelcontextprotocol/server (npm, >=2.0.0, <2.3.0; patched in 2.3.0)"
cve: "CVE-2026-111770 (GHSA-jm63-cq47-j5jp, CWE-362, CVSS 3.1 7.7)"
readTime: "3 min read"
related: ["074", "147", "108"]
---

## Summary

The MCP TypeScript server SDK, in versions 2.0.0 through 2.2.0, routed responses and notifications to a connection using only the JSON-RPC `id`. When an HTTP server created one transport or one server instance at startup and shared it across clients, messages intended for one client could reach another. Version 2.3.0 refuses shared instances.

## What was observed

The advisory was published to the repository on 15 Oct 2026 and to the GitHub Advisory Database on 20 Oct 2026. Root cause, per the advisory: "Messages were matched to a connection by JSON-RPC `id` alone." SDK clients number their requests from 0, so two clients connected to the same server instance produce colliding ids in ordinary use. A response to the request with id 0 from one client could be written to the other client's connection. The advisory classifies the flaw as a race condition (CWE-362) and scores integrity impact as low, with high confidentiality and availability impact.

```
# Illustrative
# server: transport/McpServer created once at startup, shared by all HTTP requests
# client A: request id 0 -> tool call over A's data
# client B: request id 0 -> tool call
# routing key = id only -> A's result may be delivered on B's connection
```

Exposure required multiple clients reaching the same HTTP endpoint and a shared instance. The advisory states that README examples for the Hono, Express, Fastify and Node packages showed this shared pattern until the fix. Servers built with `createMcpHandler()` and a per-call factory, stdio servers, and `@modelcontextprotocol/sdk` 1.26.0 or later were not affected. The advisory credits DavidCarliez and legitu1337 and reports no known exploitation. In an MCP server fronting document search or tenant data, the misdelivered payload is the tool result itself.

Rubric rating is high. The pattern was shown in the SDK's own examples, so copied code is likely to be vulnerable, and the leaked content is whatever the tools return to another user.

## Mitigation

Upgrade to `@modelcontextprotocol/server` 2.3.0 or later, then change the application code, since the upgrade alone breaks shared-instance servers: a second `connect()` fails with `ALREADY_CONNECTED`, and a stateless transport rejects its second request. Use a factory with `createMcpHandler()` that builds a new `McpServer` per call, build a server and transport inside each request handler, or set `sessionIdGenerator` and keep one server and transport per session. Audit deployed code that was derived from the older examples. Any per-client state routed by a client-chosen counter needs a connection identity the client cannot influence.
