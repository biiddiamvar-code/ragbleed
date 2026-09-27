---
caseId: "141"
title: "UI-TARS-desktop's @agent-infra MCP HTTP servers bound to every interface with optional auth, exposing run_command to any network client"
filed: "2026-09-27"
filedDisplay: "27 Sep 2026"
firstObserved: "01 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "ByteDance UI-TARS-desktop, @agent-infra/mcp-http-server and the @agent-infra/mcp-server-commands and @agent-infra/mcp-server-filesystem entry points (all revisions before commit c2ad42e; package version 1.2.4 unchanged across the fix)"
cve: "CVE-2026-81735"
readTime: "4 min read"
related: ["098", "133", "139"]
---

## Summary

UI-TARS-desktop ships a shared helper, `@agent-infra/mcp-http-server`, that starts the Streamable HTTP and SSE transports for its bundled MCP servers. When no host was supplied, the helper listened on `::`, every interface, and applied authentication middleware only if a caller passed some in. The commands and filesystem servers passed none. Any client that could reach the port could call `run_command`, which executed the supplied string through the shell, and could read and write files with the filesystem tools.

## What was observed

The CVE record, assigned by VulnCheck and published 27 Aug 2026 (public date 01 Jul 2026, credited to Avishai Gonen of Pluto Security), traced the flaw to `startServer.ts` in the `mcp-http-server` package. The function `startSseAndStreamableHttpMcpServer` defaulted its listen address to `::` when the caller omitted a host. Middleware, including any authentication layer, was an optional argument, applied only when present.

Two failures stacked. The bind default made the transports reachable from the network rather than only from the local machine. The auth design made protection opt-in at each call site. The `@agent-infra/mcp-server-commands` and `@agent-infra/mcp-server-filesystem` entry points called the helper with a host and port and nothing else, so both servers accepted unauthenticated MCP sessions.

```
// startServer.ts, illustrative
host = options.host ?? "::";              // all interfaces when unset
if (middlewares) app.use(...middlewares); // auth only if the caller supplied it
// mcp-server-commands: startSseAndStreamableHttpMcpServer({ port })  -> no middleware
// run_command(cmd) -> promisify(child_process.exec)(cmd)
```

The commands server's `run_command` tool handed its argument to `promisify(child_process.exec)`, so the string reached a shell unmodified. An unauthenticated JSON-RPC `tools/call` to that tool executed arbitrary commands as the user running the server. The filesystem server exposed file read and write tools under the same conditions. No model, prompt, or user interaction sat in the path; the attacker spoke MCP directly to the port.

The record carried CVSS 3.1 and 4.0 base scores of 10.0. We rated this high, the top of our scale, without divergence: the vulnerable behavior was the default, the tool surface was shell and filesystem access, and CISA's SSVC assessment marked it automatable with total technical impact.

## Mitigation

Update to a UI-TARS-desktop revision that includes commit `c2ad42e3eb9b27830db41a3e6f51ca7179d9b168` (pull request #1918), which changed the default listen address to `127.0.0.1`. The npm package version stayed at 1.2.4 across the change, so version pinning alone does not distinguish fixed from vulnerable builds; verify the source revision or rebuild from a patched checkout. Wherever these servers are started over HTTP, pass an explicit loopback host, supply authentication middleware, and block the port at the host firewall.

The fix changed the bind address, not the auth model: middleware remains optional. A loopback bind narrows exposure to local processes and to browser-based attacks such as DNS rebinding, which a bind address alone does not stop. Deployments that expose `run_command` should treat authentication as mandatory rather than rely on the new default.
