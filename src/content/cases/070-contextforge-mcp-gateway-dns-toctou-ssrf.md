---
caseId: "070"
title: "ContextForge's gateway-test endpoint checked a URL, then let DNS rebinding swap it before connecting"
filed: "2026-08-17"
filedDisplay: "17 Aug 2026"
firstObserved: "14 Aug 2026"
severity: low
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "IBM mcp-context-forge (ContextForge MCP Gateway), /admin/gateways/test endpoint (versions before 1.0.3)"
cve: "CVE-2026-53708"
readTime: "4 min read"
related: ["018", "031", "015"]
---

## Summary

ContextForge, IBM's open-source MCP gateway (package name `mcp-context-forge`), lets an administrator test a candidate MCP gateway URL from its admin panel before registering it. The test endpoint validates that the target isn't a private or internal address, then hands the same unvalidated hostname to an HTTP client that resolves DNS again on its own. An attacker who controls DNS for the domain being tested can return a public address for the validation lookup and a private one for the connection that follows, defeating the check with an ordinary DNS-rebinding race.

## What was observed

`/admin/gateways/test` resolves the hostname of a submitted URL and rejects it if that address falls inside RFC 1918 ranges, link-local space, or other private/internal blocks. That check happens once, against one DNS answer. The validated URL is then passed onward to ContextForge's HTTP client as the original hostname string — not as the IP address that was actually checked — and the HTTP client performs its own, independent DNS resolution when it opens the connection.

Nothing binds those two lookups together. A domain configured with a short TTL can answer the first query with a public IP and the second, moments later, with something like `127.0.0.1` or a cloud metadata address, and the gateway will connect to whatever the second answer says — the same DNS-rebinding pattern behind most SSRF-guard bypasses. The project's own source comments acknowledge the gap directly, flagging in two separate places that DNS is resolved once for validation and again for the actual request, with no mechanism carrying the checked IP forward.

```
# admin/gateways/test validation, illustrative
ip = resolve(hostname)          # checked here
if is_private(ip): reject()
http_client.get(url)            # hostname re-resolved independently — second lookup, no IP binding
```

Reaching the endpoint requires admin-level access to ContextForge in the first place; this isn't a pre-auth path into the gateway. What it buys an admin — or anyone who has compromised an admin session — is a way to probe the internal network the gateway sits on using the gateway's own outbound test action, sidestepping the SSRF guard that action was specifically built to enforce. That's why this one lands at low despite NVD's medium (6.6) score: the rubric weighs privileged-access requirements down, and CVSS's `PR:H` here reflects a bug that widens what an already-trusted operator can reach, not one that hands an outside attacker a foothold.

## Mitigation

Upgrade to `mcp-context-forge` 1.0.3 or later. More broadly: a DNS-based SSRF check only holds if the IP address that passed validation is the one the connection actually reaches — resolve once, then connect to that resolved address directly, or pin it via the HTTP client's connection options, rather than handing the original hostname back to a general-purpose client for a second, independent lookup. This is the same failure mode already logged in mcp-atlassian's SSRF fix (case 018): validating a URL and then letting an unrelated code path re-resolve it reopens the window every time.
