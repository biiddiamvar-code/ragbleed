---
caseId: "142"
title: "mcp-go's HTTP and SSE transports never checked the Host header, letting DNS-rebinding pages call tools on loopback MCP servers"
filed: "2026-09-27"
filedDisplay: "27 Sep 2026"
firstObserved: "26 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mark3labs mcp-go (Go module github.com/mark3labs/mcp-go, all versions < 0.56.0), StreamableHTTPServer and SSEServer transports; downstream MCP servers built on those transports"
cve: "CVE-2026-81092"
readTime: "4 min read"
related: ["139", "074", "141"]
---

## Summary

mcp-go is a widely used Go SDK for building MCP servers. Before 0.56.0, its Streamable HTTP and SSE transports served every request that arrived over a loopback connection without checking which host the request named, and the SSE transport's default cross-origin policy allowed any origin. A web page that rebound its own hostname to `127.0.0.1` could therefore reach a local mcp-go server from the operator's browser and invoke its tools. The flaw sat in the SDK, so it was inherited by every server that used these transports.

## What was observed

The CVE record, assigned by VulnCheck and published 27 Aug 2026 (public date 26 Aug 2026, credited to Avishai Gonen of Pluto Security), named two handlers: `StreamableHTTPServer.ServeHTTP` in `server/streamable_http.go` and `SSEServer.ServeHTTP` in `server/sse.go`. Neither inspected the `Host` header. A request that arrived on the loopback interface was served regardless of the name it carried.

That gap was the entry point for DNS rebinding. The attacker served a page from a low-TTL hostname, then re-pointed that hostname at the loopback address. The browser treated subsequent requests as same-origin with the page and sent them with `Host` set to the attacker's domain. On the SSE transport, the permissive cross-origin default also meant the script could read what came back.

```
// mcp-go < 0.56.0, illustrative
func (s *StreamableHTTPServer) ServeHTTP(w, r) {
    // no check that r.Host is localhost / 127.0.0.1 / [::1]
    dispatch(r)   // tools/call, resources/read served to any rebound name
}
```

The consequence was set by each downstream server. Servers built on mcp-go commonly listen on loopback on the assumption that only local software can connect, and expose whatever tools the author wired in: repository access, database queries, cloud APIs, local files. A single visit to a hostile page gave that page the same tool access, with no model or prompt involved.

Red Hat's tracker listed affected components in shipped products, including the MCP gateway images in Red Hat Connectivity Link, the OpenShift AI CLI image, and Tempo images, most marked fix deferred at the time of writing.

The record carried CVSS 4.0 7.6 (High) and CVSS 3.1 6.8 (Medium). We rated this high. The behavior was the SDK default on both HTTP transports, it propagated to every server that did not add its own guard, and the exposed surface was the full tool set of a server trusted to hold local credentials. This matches our rating for the equivalent rebinding exposure in DBHub (case 139).

## Mitigation

Upgrade mcp-go to 0.56.0 or later (pull request #921). The release adds `server/http_localhost.go`, which rejects any loopback-bound request whose `Host` is not a loopback name, and wires it into both transports. Rebuild and redeploy downstream servers; a Go module fix does nothing until each binary is recompiled against it. Where the stdio transport is sufficient, prefer it. Where HTTP is required, add authentication rather than treating a loopback bind as an access control.

The broader lesson is that a loopback listener is reachable from any browser on the same machine. Host allowlisting is the minimum defense against rebinding, and it belongs in the SDK so that individual server authors do not each have to remember it.
