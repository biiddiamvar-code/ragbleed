---
caseId: "120"
title: "mcp-fetch's SSRF guard didn't recognize a bracketed IPv6 literal as an IP address at all"
filed: "2026-09-15"
filedDisplay: "15 Sep 2026"
firstObserved: "26 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "@kazuph/mcp-fetch (npm, through 1.6.3; no fixed release at time of writing)"
cve: "CVE-2026-80347"
readTime: "4 min read"
related: ["030", "031", "070"]
---

## Summary

mcp-fetch is a Model Context Protocol server that gives an LLM agent a `fetch` tool: the model supplies a URL, the server retrieves it, and the response goes back into the model's context. Its SSRF guard, `isSafeUrl`, is supposed to resolve the target hostname and reject anything that lands on loopback, link-local, or private-network addresses before the request goes out. A bracketed IPv6 literal — the syntax a URL uses to write `http://[::1]/` — passed through that guard as an opaque string instead of a recognized IP address, so the check that was supposed to block it never ran. The HTTP client that made the actual request stripped the brackets and connected anyway. Any agent or workflow that lets untrusted prompt content or retrieved data influence the fetch target could reach loopback services and cloud instance metadata through a tool that believed it had already filtered that out.

## What was observed

The guard's logic depended on `net.isIP()` correctly identifying the hostname as an IPv6 address. For a literal such as `[::1]`, the parsed URL object hands back the hostname with its brackets intact — `[::1]`, not `::1` — and `net.isIP()` returns `0` for that bracketed string, because it isn't a valid textual IP address on its own. A return of `0` told the guard this wasn't an IP literal at all, so the branch that checks private and loopback ranges never executed.

```
# illustrative: the guard and the HTTP client parse the same literal differently
hostname = parsed_url.hostname        # "[::1]" — brackets included
if net.isIP(hostname) != 0:           # returns 0 for a bracketed string — check skipped
    reject_if_private(hostname)
# falls through to DNS resolution, which finds nothing for "[::1]" — reported "safe"
response = http_client.get(url)       # client strips the brackets, connects to ::1
```

With the private-address branch skipped, the guard fell back to ordinary DNS resolution. A bracketed literal isn't a resolvable hostname, so the lookup returned nothing, and the code treated an unresolvable name as a safe one rather than a suspicious one. The underlying HTTP client then did what HTTP clients do with a bracketed IPv6 URL: it stripped the brackets, recognized the address, and connected to it directly. The same class of bypass extended to IPv4-mapped IPv6 literals like `[::ffff:169.254.169.254]`, since the guard's private-range check had no case for the `::ffff:0:0/96` prefix even once bracket-stripping was fixed. Reaching that specific address from a workload with an attached cloud role turns a parsing bug into direct credential theft.

The bug sits in one MCP fetch tool, but the pattern isn't unique to it — comparable bracket- and mapped-address bypasses have been reported independently in at least three other MCP fetch-style tools this year (`auth-fetch-mcp`, `mcp-searxng`, and `open-webSearch`'s `fetchWebContent`), each with its own SSRF guard written against the same blind spot in how URL parsing and IP-address validation compose.

## Mitigation

No fixed release existed for mcp-fetch at the time of writing; the maintainer's tracking issue calls for stripping brackets before calling `net.isIP`, rejecting any bracketed hostname that doesn't normalize to a valid IPv6 literal, and adding an explicit check for the IPv4-mapped `::ffff:0:0/96` range. Until a patch ships, disable the fetch tool for any agent that processes untrusted prompts or retrieved content, or place the MCP server behind an egress proxy that resolves the target itself and enforces the private/loopback/metadata blocklist at the network layer — a control that doesn't depend on the tool's own URL parsing being correct. Rated high rather than the CVSS 4.0 base score some trackers list: the mechanism requires no special network position or configuration, reaching cloud metadata is a single crafted string away, and the affected surface is any agent stack that wires an LLM's tool-calling output straight into a URL fetch — which is most of them. An SSRF guard that validates a string the network stack will later reinterpret differently isn't validating the request that actually gets sent.
