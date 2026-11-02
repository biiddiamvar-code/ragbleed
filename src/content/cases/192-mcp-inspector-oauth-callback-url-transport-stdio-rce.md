---
caseId: "192"
title: "MCP Inspector's OAuth callback page read stdio transport settings from the URL, letting a malicious MCP server launch local commands"
filed: "2026-11-02"
filedDisplay: "02 Nov 2026"
firstObserved: "21 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "@modelcontextprotocol/inspector and @modelcontextprotocol/inspector-client (npm, >=0.13.0, <=1.0.2; fixed in 1.0.3)"
cve: "No CVE assigned as of writing; GHSA-4fc4-wcmh-4g86 (CVSS 3.1 9.6)"
readTime: "3 min read"
related: ["085", "174", "147"]
---

## Summary

The OAuth callback page of MCP Inspector, the developer tool for testing MCP servers, took its connection settings from the callback URL's query string. A remote MCP server that the user connected to could redirect the browser to a crafted callback URL naming the stdio transport and an arbitrary command. After the OAuth exchange completed, Inspector reconnected using those settings, and its local proxy launched the command. The fix shipped in version 1.0.3.

## What was observed

The advisory, published 21 Oct 2026, records that the callback page read `transport`, `serverCommand`, and `serverArgs` from the URL when it loaded. It extracted the OAuth `code` for the token exchange but neither rejected nor stripped the remaining parameters. On a successful exchange it reconnected automatically with the URL-supplied values.

```
# malicious remote server completes the OAuth redirect to:
#   <inspector>/oauth/callback?code=...&transport=stdio&serverCommand=<cmd>&serverArgs=...
# callback page: exchanges code, then reconnects using the URL's transport settings
# local proxy /stdio endpoint: spawns <cmd> on the user's machine
```

No tool invocation was needed beyond connecting to the server. Inspector's proxy ran with the privileges of the developer's account, so the command executed with access to that account's files, environment variables, and credentials. The advisory affects both `@modelcontextprotocol/inspector` and `@modelcontextprotocol/inspector-client` from 0.13.0 through 1.0.2. A second critical Inspector advisory, GHSA-6x67-4w4w-9f3w, was published the same day with the same affected range; this case covers only the OAuth callback issue.

The advisory scores the issue 9.6. It is rated medium here: Inspector is a local development tool rather than a production service, and exploitation required the user to connect to an attacker-controlled server. The consequence on that workstation, however, was arbitrary command execution.

## Mitigation

Upgrade both Inspector packages to 1.0.3 or later. The advisory lists no workarounds. Its recommended design is that the callback stores connection parameters before the redirect and parses only OAuth fields (`code`, `state`, and error values) on return. Developers testing third-party or unvetted MCP servers should do so in a disposable environment without production credentials.

A page that finishes a login flow should accept a login result and nothing else.
