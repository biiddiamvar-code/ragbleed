---
caseId: "220"
title: "k8s-mcp-server started its default SSE transport on all interfaces with no authentication middleware, exposing write-capable Kubernetes and Helm tools to any network caller"
filed: "2026-11-23"
filedDisplay: "23 Nov 2026"
firstObserved: "31 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "k8s-mcp-server (Go module github.com/reza-gholizade/k8s-mcp-server, <= 1.0.25), SSE and streamable HTTP transports; fixed in 1.1.0"
cve: "CVE-2026-130007 (GHSA-m932-63jc-4jqq, CWE-306, CVSS 4.0 7.9)"
readTime: "4 min read"
related: ["145", "181", "216"]
---

## Summary

k8s-mcp-server, an MCP server that exposes Kubernetes and Helm operations as tools, defaulted to its SSE transport, bound it to all interfaces on port 8080, and started it with no authentication layer in front of the MCP endpoints. Write-capable tools were registered unless the operator passed `-read-only`. Any host that could reach the port could open a session, list the tools and call them with the server's cluster credentials. Version 1.1.0 requires a bearer token on HTTP transports, binds to loopback and makes stdio the default.

## What was observed

GHSA-m932-63jc-4jqq was published on 31 Aug 2026, crediting the reporter `bebold6133`, after a private-disclosure request in issue #131; the CVE record followed on 18 Nov 2026. The advisory traced the request path statically. In `main.go`, the server constructed `server.NewSSEServer(s)` from the mcp-go library with no authentication option and no context function, then called `sse.Start(":"+port)`, which listened on every interface. `SERVER_MODE` defaulted to `sse` and the port to 8080.

Inside mcp-go, `GET /sse` issued a session ID with no credential check, and `POST /message` gated only on the HTTP method and on that session ID being known. The advisory described the session ID as "a correlation value, not a credential." No Authorization header, token or Origin header was examined before the JSON-RPC body reached `HandleMessage`. The only header the server set was `Access-Control-Allow-Origin: *`, which widened browser access rather than restricting it.

```
# any host that can reach :8080
GET  /sse                        -> session id (no auth)
POST /message?sessionId=<id>     initialize
POST /message?sessionId=<id>     tools/list     -> full tool set
POST /message?sessionId=<id>     tools/call     -> runs with the server's kubeconfig
```

`readOnly` defaulted to false, so the registered tool set included resource creation and deletion, rollout restarts, and Helm install, upgrade, uninstall and rollback. The reporter's reproduction sent `initialize`, `tools/list` and a `tools/call` for `getAPIResources` with no authentication headers; the call failed inside the handler on a cluster-connection error, not with a 401 or 403, which established that the request had passed every gate the transport had. The maintainer's fix PR summarised the defect in one line: "The HTTP transports were started directly with no authentication middleware."

Severity is rated high. The exposure required no unusual configuration: the vulnerable state was the out-of-the-box one, and the authority it handed out was whatever RBAC the server's kubeconfig carried, including write access to workloads and Helm releases.

## Mitigation

Upgrade to k8s-mcp-server 1.1.0 or later. That release, via PR #134 (commit `817d810`), enforces bearer authentication on every SSE and streamable HTTP endpoint except `/healthz`, refuses to start when `MCP_AUTH_TOKEN` is missing or shorter than 32 characters, checks browser origins against `MCP_ALLOWED_ORIGINS`, binds HTTP transports to `127.0.0.1` unless `SERVER_HOST` is set explicitly, and switches the default transport to stdio.

On instances that ran an earlier version in SSE or HTTP mode, review the Kubernetes audit log for actions taken by the server's service account or kubeconfig identity, and rotate that credential. Run the server with `-read-only` where write tools are not needed, and scope its RBAC to the namespaces and verbs the agent actually uses.

An MCP server that wraps an administrative credential is that credential, served over HTTP. Whatever authentication it lacks, the credential lacks.
