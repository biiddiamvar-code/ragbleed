---
caseId: "087"
title: "CircleCI's MCP server treated a client-supplied Host header as its only authentication check"
filed: "2026-08-27"
filedDisplay: "27 Aug 2026"
firstObserved: "30 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "@circleci/mcp-server-circleci (standalone npm package, versions before 0.19.2)"
cve: "No CVE assigned as of disclosure (GHSA-xv5j-cwgj-22r4); researcher-assessed CVSS 3.1 10.0"
readTime: "4 min read"
related: ["042", "028", "017"]
---

## Summary

CircleCI's standalone MCP server is designed to run as a shared, network-reachable service that a whole team's AI agents connect to, carrying the organization's CircleCI API token to complete tasks on their behalf. To keep browser-based attacks out, the server checked the `Host` and `Origin` headers on incoming requests against an allowlist before handling any MCP tool call. Both headers are set by the client, and the caller attacking the server is the client — the check verified a lock the attacker already held the key to. A request with `Host: localhost` and no `Origin` header passed both checks, reached the server's tools unauthenticated, and could invoke `run_pipeline` to execute arbitrary commands inside the organization's CI environment using its own stored token. Security firm Remedio reported the issue to CircleCI on July 30, 2026; a fix shipped six days later as version 0.19.2, and the advisory (GHSA-xv5j-cwgj-22r4) went public August 10.

## What was observed

The server's origin check explicitly exempted requests carrying no `Origin` header at all, reasoning that non-browser clients such as curl or the `mcp-remote` proxy don't send one:

```
// isOriginAllowed(), as reported
if (!origin?.trim()) return true;   // no Origin -> allowed
return allowed.has(origin.trim().toLowerCase());
```

The companion `isHostAllowed()` check compared the `Host` header against the same kind of allowlist, and `localhost` was on it by default. Neither check considered that an attacker crafting a raw HTTP request controls both headers directly — there is no browser enforcing same-origin policy on their behalf, because there is no browser in the request path at all. Sending `Host: localhost` with the `Origin` header omitted satisfied both checks in a single request, regardless of where the request actually originated. The default bind made the check reachable in the first place: the server listened on `0.0.0.0` unless an operator explicitly overrode `MCP_BIND_HOST`, so any instance exposed to a shared network — the exact deployment pattern CircleCI's own documentation described for team use — accepted the forged request from anywhere that could reach the port.

From there, the path to compromise was a single legitimate tool call. `run_pipeline` accepts a pipeline configuration and executes it through CircleCI using the org's token; a configuration with an attacker-authored `run:` step exports every secret in the build environment or opens a reverse shell, and CircleCI carries out the request exactly as asked, because from the platform's perspective an authenticated MCP server made it. Two steps — one forged header, one tool call — took an unauthenticated network caller to code execution inside the organization's build environment and everything reachable from it. This was not CircleCI's first MCP server advisory of the summer: a separate flaw (GHSA-8xjg-jpfh-5257) was patched in the same package in July, and CircleCI subsequently began steering users toward a CLI-integrated MCP server with OAuth-based authentication, deprecating new feature investment in the standalone package.

## Mitigation

Upgrade the standalone `@circleci/mcp-server-circleci` package to 0.19.2 or later immediately, or migrate to the CircleCI CLI's built-in MCP server, which authenticates over OAuth rather than inspecting client-supplied headers. Any organization that ran an exposed instance before patching should rotate CircleCI project tokens and any cloud credentials reachable from build steps, since a patch stops future exploitation but does not invalidate credentials already read out through the pipeline-execution path. The broader failure mode recurs across MCP servers generally: `Host` and `Origin` headers are request metadata the client writes, not a substitute for authentication, and an MCP tool surface that can execute commands or move credentials turns that mistake directly into remote code execution rather than a lesser bug — there is no second door behind the first one to slow an attacker down.
