---
caseId: "031"
title: "ToolHive's own SSRF guards existed — but its MCP auth-discovery code never called them"
filed: "2026-07-26"
filedDisplay: "26 Jul 2026"
firstObserved: "15 Jul 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "ToolHive (all versions before 0.31.0)"
cve: "CVE-2026-58196"
readTime: "4 min read"
related: ["015", "018", "014"]
---

## Summary

ToolHive runs each MCP server it manages inside an isolated container, stripped of local credentials, specifically so a malicious or compromised MCP server can't reach anything beyond its own sandbox. That guarantee didn't extend to authentication discovery: before ToolHive launches a remote MCP server's container, its host process performs an OAuth-style metadata lookup — fetching a `resource_metadata` URL the remote server supplies and following any redirect it hands back — with no check against private IP ranges or internal hostnames. A remote MCP server added through ToolHive's ordinary workflow could steer the ToolHive host itself into fetching cloud instance metadata or other internal addresses, from outside the container boundary the tool exists to enforce.

## What was observed

ToolHive already had the guards this discovery step needed elsewhere in its own codebase. `ValidateRemoteURL` rejects internal IPs and known internal hostnames for a configured remote MCP endpoint, and a separate `IsPrivateIP` helper blocks RFC 1918 ranges, link-local addresses, `169.254.0.0/16`, and loopback for outbound requests in other parts of the tool. Neither guard was wired into the authentication-discovery client. When ToolHive connects to a remote MCP server, it fetches that server's advertised `resource_metadata` URL to learn how to authenticate — and both that URL and any redirect target it returned went unvalidated.

Because this fetch runs host-side, before the server's container is ever started, it carries none of the network isolation ToolHive applies to the servers it manages. A user doesn't need to be tricked into visiting a malicious address; they only need to connect to an MCP server they intend to use, and the attack rides entirely inside that server's own discovery response — the metadata document itself names the next URL to fetch.

```
# discovery client, unlike ValidateRemoteURL / IsPrivateIP elsewhere in the codebase,
# never checks the server-supplied resource_metadata URL or its redirect target
resp := http.Get(serverSuppliedResourceMetadataURL)  // no private-IP guard, redirects followed
```

The practical reach was internal reconnaissance and cloud-metadata access from the ToolHive host, not a direct return of secrets to the attacker — the advisory rates confidentiality impact low, since the discovery client processes the response rather than relaying it back verbatim. That's a narrower outcome than the credential-echoing SSRF pattern seen elsewhere in this database, and it's why this one lands at medium rather than the high severity a metadata-reachable SSRF often earns when the response comes straight back to the attacker.

## Mitigation

Upgrade to ToolHive 0.31.0 or later, which routes authentication discovery through the same validation guards the rest of the codebase already enforces. More generally: a codebase can build correct SSRF guards and still ship a vulnerability if those guards live in a shared helper that not every caller is required to use. Any code path where an external, semi-trusted party — here, a remote MCP server's own metadata response — hands back a URL for the host to fetch next needs the private-IP and redirect check applied at that specific call site. Proving the guard exists elsewhere in the codebase isn't the same as proving it runs.
