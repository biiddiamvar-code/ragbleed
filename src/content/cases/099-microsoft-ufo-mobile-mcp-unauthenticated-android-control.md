---
caseId: "099"
title: "Microsoft UFO's Mobile MCP servers accepted screen capture and device-control calls from anyone who could reach the port"
filed: "2026-09-02"
filedDisplay: "02 Sep 2026"
firstObserved: "10 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "microsoft/UFO (<= v3.0.7)"
cve: "CVE-2026-73296 (GHSA-24fq-m9rr-g3mm)"
readTime: "4 min read"
related: ["074", "017", "096"]
---

## Summary

Microsoft's UFO is an open-source agentic automation framework that includes two MCP servers for driving ADB-connected Android devices: one for collecting screenshots, UI trees, and device metadata, the other for injecting taps, swipes, text, and app launches. Both servers were built as plain `FastMCP` instances with no authentication provider and no request-level authorization check. UFO's own documentation described running these servers bound to `0.0.0.0` on ports 8020 and 8021 for remote deployment; anyone who followed that guidance exposed a session that any network-reachable MCP client could open and use to read a device's screen or control it outright, with no API key, no login, and no user interaction on either end.

## What was observed

The Mobile MCP data-collection server (port 8020) exposed tools including `capture_screenshot`, `get_ui_tree`, `get_device_info`, and window-control lookups. The action server (port 8021) exposed `tap`, `swipe`, `type_text`, `launch_app`, `press_key`, and `click_control`. Both sat directly in front of ADB subprocess calls with no identity check in between:

```
# tap tool, illustrative — no auth check before the ADB call
await asyncio.create_subprocess_exec(
    adb_path, "shell", "input", "tap", str(x), str(y),
)
```

`capture_screenshot` followed the same pattern: run `adb shell screencap -p`, pull the resulting file off the device, and return it to the caller as base64 — again with nothing checking who the caller was. The default CLI host was `localhost`, which limited exposure for operators who left the default alone. But UFO's own docs for remote servers and the mobile executor described binding to `0.0.0.0` as the supported way to reach these services from another machine, and once bound that way, session initialization and every tool call proceeded with no bearer token, no API key, and no distinction between an authorized UFO client and any other TCP peer. A firewall could narrow who could reach the port, but nothing at the application layer verified the caller's identity once a packet arrived.

The practical reach was full remote visibility and control of whatever the connected Android device's screen showed and accepted as input — messages, one-time codes, application contents, and arbitrary UI navigation — bounded only by the device's unlocked state, not by any credential.

## Mitigation

Upgrade to UFO 3.0.8 or later, which requires a bearer credential read from `UFO_MCP_API_KEY`, compares it in constant time, and fails startup closed if the variable is unset. Until upgraded, operators should keep both Mobile MCP services bound to localhost, block inbound access to ports 8020 and 8021 at the network layer, and front any remote deployment with TLS and an authenticated reverse proxy or private tunnel rather than exposing the raw MCP port. This site rates the mechanism high rather than matching the vendor's headline CVSS of 9.4 point for point, but lands in the same place: the flaw required following the vendor's own documented deployment path rather than an unusual misconfiguration, and the resulting access — screen contents plus full UI control with zero authentication — is exactly the kind of default-path, sensitive-data exposure this database rates high regardless of CVSS. The recurring pattern across this database's MCP entries holds again here: a tool server built to sit behind a trusted client's assumption of a private network becomes a pre-auth remote-control primitive the moment the documented deployment guidance says to expose it publicly without also shipping authentication as a default, not an opt-in.
