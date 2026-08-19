---
caseId: "074"
title: "GitHub MCP Server's lockdown-mode cache let one user's session decide trust for everyone else's"
filed: "2026-08-19"
filedDisplay: "19 Aug 2026"
firstObserved: "09 Jun 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "github-mcp-server (gomod, >=0.22.0, <1.1.2), HTTP transport with --lockdown-mode enabled"
cve: "CVE-2026-48529 (GHSA-pjp5-fpmr-3349)"
readTime: "5 min read"
related: ["016", "038", "055"]
---

## Summary

GitHub MCP Server's lockdown mode exists to protect AI coding agents from indirect prompt injection: before handing an agent the text of an issue, pull request, or comment written by an external contributor, it checks whether that contributor has push access to the repository, and sanitizes the content if they don't. Running the server in HTTP mode for multi-user deployment — the configuration behind GitHub Copilot's managed MCP endpoint — the component that performs this check was implemented as a process-global singleton initialized once, from the first authenticated user's credentials, and never updated afterward. Every subsequent user's trust decisions were evaluated using the first user's GitHub identity instead of their own. Fixed in 1.1.2.

## What was observed

The access-check cache, `RepoAccessCache`, is created through a `GetInstance` function guarded by a mutex but not by caller identity:

```
// pkg/lockdown/lockdown.go
func GetInstance(client *githubv4.Client, opts ...RepoAccessOption) *RepoAccessCache {
    instanceMu.Lock()
    defer instanceMu.Unlock()
    if instance == nil {
        instance = &RepoAccessCache{client: client}  // only stored on first call
    }
    return instance  // every later caller gets this same object, and client is ignored
}
```

In HTTP mode, the server calls this once per incoming request, constructing a fresh GraphQL client scoped to that request's token — but `GetInstance` discards every client after the first and keeps returning the object built from whichever user's request happened to initialize the process. A proof of concept published with the advisory confirmed two distinct, differently-tokened GraphQL clients resolve to the same singleton pointer.

The cache backs `IsSafeContent`, called from at least six places in the issue- and pull-request-reading code to decide whether externally authored text reaches the model raw or gets sanitized first. Three failure modes followed from the same root cause: the cached `ViewerLogin` field, compared against each request's actual username to decide the check's outcome, stayed fixed at the first user's login for every later comparison; repository visibility and push-access data — the actual signal the sanitization decision turns on — was evaluated once through the first user's view of a repository and then applied to every other user regardless of what they could individually see, so a repository private to one user but visible to another produced the wrong trust decision for whichever of the two didn't initialize the cache; and once the first user's token expired or was revoked, every subsequent lockdown check failed outright, which — because errors from this path are treated conservatively — broke the protection for the whole process until restart.

## Mitigation

Upgrade to github-mcp-server 1.1.2 or later, which scopes the access cache per request instead of per process. This site rates the mechanism medium against the advisory's own CVSS 6.0: reaching it requires HTTP-mode, multi-user deployment with lockdown enabled — not the default for a locally run MCP server, though it is the intended shape for a shared, managed endpoint — and the confirmed impact is a wrong trust decision rather than direct credential or data disclosure. The broader lesson: a cache built to avoid re-authenticating on every call has to be keyed by the caller's identity, not by "first caller wins," the moment a server starts handling more than one authenticated user in the same process — a distinction easy to miss when the code was first written for a single-user CLI and later wrapped in an HTTP server without revisiting that assumption.
