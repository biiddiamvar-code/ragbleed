---
caseId: "216"
title: "jupyter-mcp-server enforced MCP_TOKEN on /mcp but not on the /api/connect and /api/stop routes mounted beside it, letting unauthenticated callers repoint the notebook backend"
filed: "2026-11-21"
filedDisplay: "21 Nov 2026"
firstObserved: "11 Jul 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "jupyter-mcp-server (datalayer/jupyter-mcp-server, <= 1.0.2, standalone streamable-http mode; fixed in 1.0.3 per the CVE record)"
cve: "CVE-2026-77318 (GHSA-24pw-rf5p-mgp7, CWE-306, CVSS 4.0 7.3)"
readTime: "3 min read"
related: ["133", "017", "096"]
---

## Summary

jupyter-mcp-server, an MCP server that lets agents read, edit and execute Jupyter notebooks, required the configured `MCP_TOKEN` on its `/mcp` endpoint but mounted two state-changing management routes on the same application without any authentication check. An unauthenticated network caller could use `PUT /api/connect` to replace the server's Jupyter runtime and document targets, and `DELETE /api/stop` to stop the active kernel. The flaw affected the hardened configuration, with a token set, not only the explicit no-auth mode.

## What was observed

The project published GHSA-24pw-rf5p-mgp7 on 11 Jul 2026, crediting reporters avishaigonen-pluto and yotampe-pluto. CVE-2026-77318 was published on 19 Nov 2026, listing versions before 1.0.3 as affected.

In standalone streamable-http mode the server's token middleware covered the MCP protocol endpoint only. The management routes were registered separately as custom routes (`@mcp.custom_route("/api/connect", ["PUT"])` in `server.py`) and carried no token check of their own. The CLI already refused to start streamable-http without a token unless `--insecure-mcp-noauth` was passed, so operators running with `MCP_TOKEN` set had reason to believe the whole listener was authenticated. The advisory's proof ran with the token configured.

```
# server started with MCP_TOKEN set, standalone streamable-http
POST   /mcp           -> rejected without token      # protected
PUT    /api/connect   -> accepted without token     # new runtime_url / document_url / tokens
DELETE /api/stop      -> accepted without token     # active kernel stopped
# after connect: server opens a kernel client against the caller-chosen backend
```

A successful `PUT /api/connect` replaced the runtime and document URLs and their tokens, reset the server context and started a kernel client against the supplied backend. The advisory's proof showed the server then sending Jupyter API traffic, including `POST /api/kernels`, to the attacker's host with an attacker-chosen bearer token. From that point the agent's notebook reads, cell writes and execution requests went to infrastructure the attacker controlled, which could log them and return arbitrary notebook content and cell output to the agent. The advisory notes that the default `0.0.0.0` bind widened exposure. It does not claim code execution on the host running the MCP server.

Severity is rated medium, below the CVSS 4.0 score of 7.3. The configuration was a common one and no credentials were needed, but the reachable effect was redirection and interception of the agent's notebook session plus a denial of service on the kernel, not direct access to stored data on the server.

## Mitigation

Upgrade jupyter-mcp-server to 1.0.3 or later; the current 2.x line is preferable. Note that the GitHub advisory page itself lists no patched version, so confirm the installed release requires the token on `/api/connect` and `/api/stop` before relying on it. Until upgraded, bind the server to `127.0.0.1` or place it behind a reverse proxy that authenticates every path, not only `/mcp`, and restrict egress from the MCP host so a replaced runtime URL cannot reach arbitrary hosts.

Authentication scoped to a protocol endpoint protects that endpoint; every other route on the same listener needs its own check.
