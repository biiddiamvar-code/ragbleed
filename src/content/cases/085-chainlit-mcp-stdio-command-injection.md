---
caseId: "085"
title: "Chainlit's MCP stdio launcher allowlisted the executable name and let every argument through unchecked"
filed: "2026-08-26"
filedDisplay: "26 Aug 2026"
firstObserved: "25 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Chainlit (pip package, >=2.4.0-rc.0, <2.12.0), MCP stdio transport (features.mcp.enabled = true)"
cve: "CVE-2026-45018 (GHSA-w3fx-mc44-mf6j)"
readTime: "4 min read"
related: ["028", "042", "056"]
---

## Summary

Chainlit is a Python framework for building chat interfaces in front of LLM and RAG backends, with built-in support for connecting those chats to MCP servers. When MCP was enabled, its `POST /mcp` endpoint accepted a user-controlled command string for launching stdio-transport MCP servers and checked that string against an allowlist before running it. The check only inspected the executable name; it never inspected or restricted the arguments that followed. An unauthenticated caller could supply an allowlisted executable name paired with arguments that ran an arbitrary shell command, reaching remote code execution on the Chainlit server with no credentials at all. Fixed in Chainlit 2.12.0 as CVE-2026-45018, rated CVSS 9.8.

## What was observed

Chainlit's `validate_mcp_command()` function existed to keep the stdio MCP launcher from spawning arbitrary processes: it took the submitted `fullCommand` string, split out the executable, and compared that executable against a configurable allowlist of permitted binaries such as `npx`. Everything after the executable name — the argument list — passed through unexamined, on the assumption that constraining the binary was enough to constrain what the launched process could do.

That assumption doesn't hold for executables like `npx`, which accept flags that execute code directly rather than merely locating and running a package. A command string built as an allowlisted executable followed by a flag-and-payload pair — for example `npx -y -c 'ARBITRARY COMMAND'` — passed the allowlist check on the executable name alone and then ran the attacker's shell command with the privileges of the Chainlit process.

```
# validate_mcp_command(), illustrative
executable, *args = shlex.split(full_command)
if executable not in ALLOWED_EXECUTABLES:
    reject()
# args never inspected — a code-executing flag rides through untouched
spawn(full_command)
```

The endpoint required no authentication, so any network caller who could reach `/mcp` on a Chainlit deployment with MCP enabled could trigger this directly. Chainlit's MCP integration exists specifically to let a chat interface hand off to external tool servers — the same feature surface that makes MCP integrations broadly useful is what made this endpoint reachable without a login. A companion flaw fixed in the same release, CVE-2026-45019, left the SSE and streamable-HTTP MCP transports accepting an unvalidated target URL and headers, enabling unauthenticated SSRF against internal services and cloud metadata endpoints through the same unauthenticated surface.

## Mitigation

Upgrade to Chainlit 2.12.0 or later, which fixes both the stdio command injection (CVE-2026-45018) and the SSE/streamable-HTTP SSRF (CVE-2026-45019). Where upgrading isn't immediate, disable `features.mcp.enabled` or place the `/mcp` endpoint behind authentication and network restrictions rather than relying on the built-in allowlist. The broader lesson: an allowlist that checks only the program name and not its arguments isn't validating what will actually run — tools like `npx`, `python`, and `sh` all expose flags that turn "run this approved binary" into "run whatever the caller wants," so any command-construction allowlist has to account for argument-level code execution, not just the entry on the binary's own name.
