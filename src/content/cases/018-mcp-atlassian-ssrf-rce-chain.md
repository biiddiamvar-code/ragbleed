---
caseId: "018"
title: "mcp-atlassian's SSRF and file-write flaws chained into a two-request root shell"
filed: "2026-03-02"
filedDisplay: "02 Mar 2026"
firstObserved: "24 Feb 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp-atlassian (versions prior to 0.17.0, HTTP/SSE transport deployments)"
cve: "CVE-2026-27825 (arbitrary file write, CVSS 9.1); CVE-2026-27826 (SSRF, CVSS 8.2) — disclosed together as \"MCPwnfluence\""
readTime: "6 min read"
related: ["017", "015", "014"]
---

## Summary

mcp-atlassian, the most widely used MCP server for connecting AI tools to Jira and Confluence, shipped with an HTTP transport mode that bound to every network interface with no authentication at all. Two separate flaws in that server — one letting a custom header redirect its outbound requests anywhere, the other letting a file-download path escape its intended directory — combined into a chain requiring exactly two HTTP requests to reach code execution on the host.

## What was observed

mcp-atlassian accepts a header that tells it which Confluence instance to talk to, to support organizations running on-prem deployments rather than Atlassian's own cloud. That header's value was trusted without validation. Pointing it at a server the attacker controlled meant the MCP server's own outbound requests — including its authentication headers — went wherever the attacker chose instead of the real Confluence instance. That's the SSRF half: a credential-harvesting and internal-network-probing primitive on its own, reachable with a single unauthenticated request.

The second half turned that primitive into something worse. The logic behind Confluence attachment downloads was missing directory confinement — it didn't check that the path it was about to write to actually stayed inside the folder it was supposed to. Combined with the first flaw, an attacker's fake "Confluence" server could hand back an "attachment" whose filename was actually a path traversal sequence, and the MCP server would write its content wherever that path pointed — `~/.bashrc`, `~/.ssh/authorized_keys`, a cron directory.

```
Request 1: set X-Atlassian-Confluence-Url to attacker's server (SSRF)
Request 2: request an "attachment" — attacker's server returns content
           with a path-traversal filename; mcp-atlassian writes it
           outside its intended directory
# result: attacker-controlled content, attacker-chosen path, no auth
```

Two requests, no credentials, and — because the server bound to `0.0.0.0` by default — reachable by anyone sharing the same office network, coworking space, or cloud VPC as the machine running it. Once a malicious cron entry or SSH key lands, the attacker has a foothold on the host itself, with everything that machine can reach: cloud credentials, internal APIs, CI/CD systems, source repositories.

## Mitigation

Upgrade to mcp-atlassian 0.17.0 or later, which adds path normalization, symlink resolution, base-directory enforcement, URL validation, scheme allowlisting, private-IP blocking, DNS validation, and redirect validation — a genuinely comprehensive fix, not a single patched line. Independent of the upgrade: never run an MCP server's HTTP transport bound to `0.0.0.0` without its own authentication layer in front of it, and treat "it's just a local dev tool" as a description that stops being true the moment the process is reachable from a shared network. If you're running any MCP server for convenience during setup, confirm what interface it's actually listening on before assuming its reach matches your intent.
