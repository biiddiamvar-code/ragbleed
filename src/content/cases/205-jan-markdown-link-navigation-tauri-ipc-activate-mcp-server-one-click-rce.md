---
caseId: "205"
title: "Jan rendered model and tool output links as same-frame anchors, letting a click load an attacker page into the Tauri window and invoke activate_mcp_server to spawn processes"
filed: "2026-11-10"
filedDisplay: "10 Nov 2026"
firstObserved: "29 Oct 2026"
severity: medium
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "Jan desktop app, janhq/jan (<=0.8.7; patched in 0.8.8)"
cve: "No CVE assigned as of writing; tracked as GHSA-j6hv-vhmg-vpj6 (CWE-94 / CWE-346 / CWE-1188, rated Critical in the advisory)"
readTime: "3 min read"
related: ["114", "092", "192"]
---

## Summary

Jan, a desktop application for running local LLMs, rendered links found in model or tool output as ordinary anchors that navigated the main application window. The window had no navigation guard, so a single click loaded an attacker-controlled page inside it. Tauri's IPC bridge was available to that page, and the `activate_mcp_server` command spawned processes from caller-supplied commands without an allowlist. Version 0.8.8 contains the fix.

## What was observed

The advisory was published on 29 Oct 2026 and credits 0xParth as reporter. It describes a five-link chain. Markdown links from model or tool output were rendered as same-frame anchors with link safety disabled. The main window had no navigation guard, so the click replaced the application page with a remote origin. Tauri's IPC bridge was injected into that remote page, and because Jan shipped no app permissions manifest, app commands were not access-controlled for remote origins. The advisory attributes the latter to Jan's use of Tauri 2.10.3, which predates the 2.11.0 fix. Finally, `activate_mcp_server` passed command, arguments, and environment variables to process spawning with no allowlist.

```
# Illustrative
# malicious MCP server or injected tool text emits a markdown link
# one click -> main window navigates to attacker origin, IPC bridge present
# page invokes activate_mcp_server(command, args, env) -> process spawned
```

The precondition is a connected malicious or compromised MCP server, or prompt-injected content reaching the chat, plus one user click. No further prompt appears. Prompt injection here is the delivery path, not the flaw: the defect is that untrusted output could change the origin of a window holding privileged native commands.

The advisory rates the issue Critical. Under the site rubric it is rated medium. Exploitation needs a hostile tool source and a user interaction, and the affected population is a desktop application rather than a shared service, though the outcome is arbitrary process execution as the user.

## Mitigation

Upgrade Jan to 0.8.8. The advisory lists independent hardening measures: a navigation guard on the main window, opening links in the external browser, an app permissions manifest restricting commands for remote origins, Tauri 2.11.0 or later, and an allowlist on the `activate_mcp_server` path. It lists no separate workaround for 0.8.7 and earlier. Until upgraded, connect only MCP servers that are trusted and avoid clicking links in model or tool output.

An application that renders untrusted model output and also exposes native commands to its web view must treat every navigation as a privilege boundary.
