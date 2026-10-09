---
caseId: "157"
title: "Obot's checkUI deny list omitted the /mcp-connect-composite/ route, letting basic-role users bypass MCP access control rules"
filed: "2026-10-09"
filedDisplay: "09 Oct 2026"
firstObserved: "01 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "Obot MCP gateway (obot-platform/obot, 0.21.1 through 0.24.1 inclusive)"
cve: "CVE-2026-103758 (GHSA-6fwv-3h4c-37j9, CVSS 4.0 8.6, CVSS 3.1 8.1)"
readTime: "3 min read"
related: ["014", "102", "087"]
---

## Summary

Obot, an MCP gateway, enforced its Access Control Rules by routing requests through a UI authorization check backed by a deny list of path prefixes. The list did not include the `/mcp-connect-composite/` route, which reaches the same proxy as the covered `/mcp-connect/` route. A user with the basic role who held a composite MCP ID could invoke tools on MCP servers the rules were meant to restrict.

## What was observed

The CVE was published on 01 Oct 2026 and is classified as CWE-863, incorrect authorization. The reporter is credited as arpitjain099.

Obot proxies MCP traffic to upstream servers using `mcpGateway.Proxy`. Access to individual servers is meant to be governed by Access Control Rules. A function named `checkUI` decides whether a request path belongs to the UI surface and should be handled under a different authorization regime. Per the advisory, the deny list inside that check named the single-server connect route but not its composite counterpart. Requests to `/mcp-connect-composite/` therefore passed the check and reached the proxy without the Access Control Rules being evaluated.

```
# Illustrative
# authenticated user, role: basic
# request path: /mcp-connect-composite/<composite-mcp-id>
# checkUI deny list: "/mcp-connect/" present, "/mcp-connect-composite/" absent
# -> request forwarded to mcpGateway.Proxy; tool calls reach restricted upstream servers
```

The same product had an earlier advisory, GHSA-vw82-7fv8-r6gp, in which the `/mcp-connect/{mcp_id}` route did not enforce Access Control Rules because the UI authorization check granted access. The composite-route finding follows the same pattern against a sibling path. A fixed version was not stated in the CVE record or the VulnCheck entry reviewed for this case, and the GitHub advisory page could not be retrieved, so the patched release could not be independently verified.

The rubric rating is medium, below the CVSS 4.0 score of 8.6. Exploitation requires an authenticated account and knowledge of a composite MCP ID. The exposure is tool invocation on servers the operator restricted, which can include write tools, but the advisory does not describe an unauthenticated path or a default configuration that exposes it. CISA's SSVC entry listed exploitation as none and no public exploit was reported.

## Mitigation

Upgrade to the latest Obot release that addresses CVE-2026-103758 and confirm the fixed version against the GHSA-6fwv-3h4c-37j9 advisory. Until then, add `/mcp-connect-composite/` to the `checkUI` deny list where the source is under operator control, and enforce authentication and authorization on the upstream MCP servers independently of the gateway.

A path deny list fails open for every route added after it was written. Authorization applied per route prefix needs an allow-by-default-deny structure, or a test that enumerates every registered route against the policy.
