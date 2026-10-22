---
caseId: "180"
title: "Claude Agent SDK passed the resume option to the CLI unvalidated, letting a leading dash inject an --mcp-config flag and execute commands"
filed: "2026-10-22"
filedDisplay: "22 Oct 2026"
firstObserved: "12 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "claude-agent-sdk (PyPI, <0.2.121; patched in 0.2.121)"
cve: "CVE-2026-96620 (GHSA-h4mw-j7qp-8mwm, CWE-20 / CWE-78 / CWE-88, CVSS 4.0 9.2)"
readTime: "3 min read"
related: ["085", "174", "056"]
---

## Summary

The Python Claude Agent SDK forwarded its `resume` option to the Claude CLI without validation. A value beginning with `-` was parsed by the CLI as a separate flag, so an attacker who controlled the value could supply `--mcp-config` and define a stdio MCP server. The CLI executed that server's command at startup, bypassing the SDK's permission controls. Version 0.2.121 contains the fix.

## What was observed

The advisory was published to the repository on 12 Sep 2026 and to the GitHub Advisory Database on 16 Oct 2026. Root cause, per the advisory: the `resume` value was passed to the CLI as an argument with no check, which made it an argument injection (CWE-88) leading to command execution (CWE-78). A stdio MCP server entry names a command and arguments that the CLI launches as a child process, so an injected configuration is equivalent to a command of the attacker's choosing, run before any tool-permission prompt applies.

```
# Illustrative
# app: session_id = request.json["session"]   # untrusted
#      options = ClaudeAgentOptions(resume=session_id)
# session_id begins with "-"  -> read as a CLI flag, not a session identifier
# injected --mcp-config defines a stdio server -> command runs at CLI startup
```

Exploitation required an application that passed untrusted input as the session identifier to `resume`. The advisory lists no workaround and no known exploitation, credits the report to hackerone.com/moamenmahmood, and links pull request #1123 and commit 347a1cb. The advisory scores the flaw 9.2 (critical). Agent backends that expose a "resume conversation" parameter to end users, common in chat front ends over retrieval pipelines, are the realistic carriers.

Rubric rating is medium, below the CVSS headline. Exposure depends on an application choosing to forward a client-controlled string into `resume`; the SDK default does not expose the path. Where an application does, the result is command execution on the host.

## Mitigation

Upgrade to `claude-agent-sdk` 0.2.121 or later. In application code, treat session identifiers as opaque server-issued values: look them up in a server-side table of sessions owned by the caller rather than passing request data through, and reject any value not matching the expected identifier format, including anything starting with `-`. Audit other SDK options that are forwarded to a subprocess command line for the same pattern. Any wrapper that builds a CLI invocation from request fields needs an allowlist at the boundary, because the downstream program cannot distinguish a value from a flag.
