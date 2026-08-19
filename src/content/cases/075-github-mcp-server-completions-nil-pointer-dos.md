---
caseId: "075"
title: "A missing nil check in GitHub MCP Server's autocomplete handler let one unauthenticated request kill the process"
filed: "2026-08-19"
filedDisplay: "19 Aug 2026"
firstObserved: "20 Jul 2026"
severity: high
category: "Denial of service / resource exhaustion"
status: "Disclosed, patch guidance pending"
affectedSystems: "github-mcp-server (gomod, <=0.33.0 and latest main; no patched version at time of writing)"
cve: "CVE-2026-47427 (GHSA-w4q6-qw23-4rg7)"
readTime: "4 min read"
related: ["029", "061", "074"]
---

## Summary

GitHub MCP Server's handler for the MCP `completion/complete` method — used to autocomplete prompt or resource arguments — read a field off the incoming request without checking it was present first. A request with an empty or missing `ref` parameter caused a nil pointer dereference, and the resulting Go panic is unrecoverable: it kills the entire server process, not just the connection that triggered it. The crash path runs ahead of any authentication check, so any client able to complete the MCP handshake and send one malformed JSON-RPC message could take the server down. No patched release exists as of this writing, seven months after the initial report.

## What was observed

`CompletionsHandler`, in `pkg/github/server.go`, accessed `params.Ref` before confirming `params` or `params.Ref` was non-nil:

```
// pkg/github/server.go — pre-fix
func (s *Server) CompletionsHandler(ctx context.Context, params *mcp.CompleteParams) (*mcp.CompleteResult, error) {
    ref := params.Ref.URI  // no nil check on params or params.Ref
    ...
}
```

Either an empty `params` object or a `params` object missing the `ref` field reaches this line and dereferences a nil pointer, which Go turns into a runtime panic. Because the dereference happens inside the request handler itself rather than in a goroutine wrapped with recovery, the panic is unrecoverable and terminates the process — every other in-flight and future request on that server instance goes down with it, not just the one that sent the bad frame. The advisory's authors ran automated fuzzing against the server with 925 generated test cases and recorded 108 crashes, an 11.7% crash rate, indicating the same class of unchecked-field-access bug is not confined to this one handler.

The report was filed in February 2026 and went unacknowledged through a follow-up email and a re-verification against a later release; GitHub Security Lab published the advisory itself in July after 44 days without a response. As of publication, no fixed version has shipped.

## Mitigation

No upgrade path exists yet. Operators running github-mcp-server in HTTP mode — particularly shared, multi-user deployments such as an organization's managed Copilot MCP endpoint — should restrict network reachability to trusted clients and monitor for process restarts, since a single crafted message from any client that can reach the port takes the whole server down regardless of that client's authorization. This site rates the mechanism high, in line with the advisory's own CVSS 7.5 rather than below it as with narrower single-worker DoS bugs elsewhere in this database (see case 029): a crash here is not scoped to one request or one worker that recovers on its own — it is a full, unauthenticated process kill, reachable pre-auth, against a component increasingly deployed as a shared endpoint serving many users at once. The immediate fix is a nil check; the durable fix is treating every field of an externally supplied MCP request as untrusted and absent until proven otherwise, since a protocol handler that panics on a missing optional field will keep finding new fields to panic on.
