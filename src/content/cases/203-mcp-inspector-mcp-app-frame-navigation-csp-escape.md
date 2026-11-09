---
caseId: "203"
title: "MCP Inspector's MCP App sandbox kept relaying host messages after the app navigated its own frame, bypassing its CSP egress limits"
filed: "2026-11-09"
filedDisplay: "09 Nov 2026"
firstObserved: "05 Nov 2026"
severity: low
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "@modelcontextprotocol/inspector (>=2.0.0, <=2.13.0; patched in 2.14.0); web client Apps tab only"
cve: "No CVE assigned as of writing; tracked as GHSA-h9j8-vj8g-v3gg (CWE-693 / CWE-940, CVSS 3.1 6.1)"
readTime: "3 min read"
related: ["192", "114", "092"]
---

## Summary

MCP Inspector's web client renders MCP Apps, HTML interfaces supplied by an MCP server, inside a sandboxed frame governed by a Content Security Policy. On the default opaque-origin path, an app could navigate its own frame to an attacker-controlled URL. The sandbox flags survived the navigation, the message proxy kept trusting the frame, and host messages continued to flow to it. Version 2.14.0 contains the fix.

## What was observed

The advisory was published on 05 Nov 2026 and credits CloneOfAlex as reporter. Per the advisory, the app is loaded into a `srcdoc` frame, and an app can set that frame's location to another URL. After navigation the new page still had a null origin and still passed the proxy's `event.source` check, so the proxy kept relaying host messages to it with `targetOrigin "*"`. A code comment in the relay assumed a `srcdoc` frame could not navigate without `allow-top-navigation`; the advisory states that this flag governs only the top window.

```
# Illustrative
# MCP App (CSP: connect-src 'none') sets its own frame location to attacker URL
# sandbox flags persist -> origin stays null -> event.source check still passes
# proxy relays host messages to the new page; page can post tools/call back
```

In the reporter's reproduction, run with `connect-src 'none'`, the attacker origin received data from the app despite the connect restriction, then received the host's next tool result, including private tool output. The host also accepted a `tools/call` posted by the attacker page as though the app had sent it. The per-app `connectDomains` allowlist was therefore not a reliable egress boundary.

Affected users were those rendering an untrusted MCP App in the web client's Apps tab, typically from a malicious or compromised MCP server. The CLI and TUI, users who never open the Apps tab, and apps that request a dedicated origin through `_meta.ui.domain` were not affected. The advisory describes no remote access to the Inspector itself.

The category is the closest fit in the site taxonomy: attacker-controlled server content reaches model-adjacent tool output and tool invocation. The mechanism is rated low. Exposure requires a developer tool, a user who connects to a hostile server and opens its app, and a UI interaction, and the advisory's CVSS 3.1 score is 6.1.

## Mitigation

Upgrade `@modelcontextprotocol/inspector` to 2.14.0. The advisory's suggested fix has the proxy treat any frame load after the first on the `srcdoc` path as navigation away, stop relaying in both directions, blank the frame, and report an error to the host. It also recommends documenting that a CSP cannot stop frame navigation. Until upgraded, avoid opening the Apps tab for MCP servers that are not trusted.

An allowlist enforced by a CSP bounds what a page loads, not where its frame goes. A sandbox that relays privileged messages must verify frame identity on every message, not only at load.
