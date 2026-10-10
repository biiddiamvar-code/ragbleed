---
caseId: "160"
title: "mcp-server-fetch retrieved model-supplied URLs with redirects enabled and no private-address validation"
filed: "2026-10-10"
filedDisplay: "10 Oct 2026"
firstObserved: "02 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "mcp-server-fetch and mcp-server-everything (modelcontextprotocol/servers, versions 2026.6.0 through 2026.6.4); no released fix at time of writing"
cve: "CVE-2026-104120 (VulDB VDB-412764, CWE-918, CNA: VulDB)"
readTime: "3 min read"
related: ["120", "030", "031"]
---

## Summary

The reference `mcp-server-fetch` gives an LLM agent a tool that retrieves a URL and returns the content. In the affected releases the server performed no validation of the destination address and followed redirects. A URL supplied by the model, or by content that influenced the model, could therefore target loopback services, private networks, and cloud metadata endpoints. At the time of writing a fix existed only as an unmerged draft pull request. The CVE record itself gives little mechanism detail; the root cause below is taken from the referenced pull request.

## What was observed

The CVE was published by VulDB on 02 Oct 2026. It describes a server-side request forgery in the `fetch_url` function of `mcp_server_fetch/server.py`, reachable by manipulating the URL argument, and lists versions 2026.6.0 through 2026.6.4 of `mcp-server-fetch` and `mcp-server-everything` as affected. References include GitHub issue #4492, tagged as the exploit, and pull request #4890, tagged as the patch. The record was reported by a VulDB user and carries a CVSS 4.0 score of 6.9 and a CVSS 3.1 score of 7.3.

The pull request, opened on 28 Sep 2026, describes the mechanism. The server fetched the supplied URL with redirects enabled and performed no egress IP validation, so direct requests and open-redirect chains could reach loopback, RFC 1918, and link-local addresses, including metadata endpoints such as 169.254.169.254 and 100.100.100.100. The proposed change checks the hostname before connecting and again on every redirect hop, and blocks private, loopback, link-local, and metadata addresses. It adds an `FETCH_ALLOW_PRIVATE_IPS=1` override for local development.

```
# Illustrative
# agent calls fetch with url=http://169.254.169.254/latest/meta-data/...
# (or a public URL that redirects to it)
# server: no destination check, redirects followed
# response body is returned into the model context
```

The pull request states a limitation: the check runs before the connection, not at the socket level, so DNS rebinding between resolution and connection is not fully prevented. As of 29 Sep 2026 the pull request was an unmerged draft, and its author had asked maintainers whether the protection should be on by default, opt-in, or absent. The record says a public exploit exists, while a second source lists no public proof of concept; this was not reconciled.

The rubric rating is medium. The server typically runs as a local stdio process, and the data reachable depends on the host, but cloud-hosted agent deployments expose instance credentials through the same call. Case 120 documents a bypass of an SSRF guard in a different fetch server; this case is the absence of a guard.

## Mitigation

No released fix was identified. Until one ships, disable the fetch tool for agents that process untrusted prompts or retrieved content, or run the server behind an egress proxy that resolves destinations itself and blocks private, loopback, link-local, and metadata ranges at the network layer. Require IMDSv2 or equivalent metadata protections on hosts running agent tooling. Track pull request #4890 for the upstream resolution, and treat any default-off outcome as a configuration requirement for operators.

A fetch tool that validates nothing is a proxy to every address the host can reach.
