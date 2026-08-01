---
caseId: "042"
title: "Ruflo's MCP bridge exposed 233 tools over HTTP with no authentication at all"
filed: "2026-08-01"
filedDisplay: "01 Aug 2026"
firstObserved: "29 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Ruflo (all versions before 3.16.3), MCP Bridge component (Express.js server, default docker-compose binding on port 3001)"
cve: "CVE-2026-59726 (\"RufRoot\")"
readTime: "5 min read"
related: ["006", "028", "038"]
---

## Summary

Ruflo, an open-source AI agent orchestration platform, ships an MCP Bridge — an Express.js server that routes every tool call, agent action, and memory operation through a single HTTP endpoint. That endpoint, `POST /mcp`, accepted MCP JSON-RPC tool invocations and passed them straight to the tool executor with no authentication layer at any point in the request path. Because the default docker-compose configuration binds the bridge to `0.0.0.0:3001`, any network-reachable deployment allowed an unauthenticated caller to invoke any of the platform's 233 exposed tools, including one that ran arbitrary shell commands inside the container. Noma Labs disclosed the issue on 30 June 2026; a fix shipped within 24 hours, and the advisory was published 29 July 2026 as CVE-2026-59726, CVSS 10.0.

## What was observed

The MCP Bridge exposed `tools/list` and `tools/call` without checking who was calling. A single unauthenticated POST to `tools/call` naming the `ruflo__terminal_execute` tool ran the supplied command as the container's `node` user:

```
# no token, no API key, no header check, no IP allowlist —
# one POST request to /mcp was sufficient for command execution
curl -X POST http://target:3001/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"ruflo__terminal_execute",
                 "arguments":{"command":"id && hostname"}}}'
```

A command blocklist existed (`AUTOPILOT_BLOCKED_PATTERNS`), but it was only enforced inside Ruflo's autopilot flow; the `/mcp` endpoint bypassed it entirely. From that first shell, escalation to full compromise required no further vulnerabilities, only more requests to the same endpoint. The container's docker-compose configuration passed every configured LLM provider key (OpenAI, Anthropic, Google, OpenRouter) into the process environment, and the backend inherited that environment wholesale, so a single `printenv` exposed all of them. Those stolen keys and the container's own compute could then be used to spawn attacker-controlled agent swarms through the same unauthenticated tool interface. The MCP Bridge also exposed a tool for writing entries into Ruflo's persistent memory store (AgentDB), which researchers used to inject a fabricated policy statement designed to influence the content of future agent-generated output — a poisoning step that survives a version upgrade, since patching the code does not undo data already written to the store. A local MongoDB instance, reachable on the internal Docker network without authentication, held full conversation history and was dumped directly. Finally, because the main application file was read-only but its containing directory was not, researchers wrote a persistence script, hooked it into the startup path, and relied on the container's restart policy to keep it running across crashes.

## Mitigation

Upgrade to Ruflo 3.16.3 or later. The fix set (ADR-166) binds the MCP bridge to loopback by default and fails closed if a public bind is requested without an auth token configured, adds constant-time bearer-token authentication, gates the terminal-execution tool behind an explicit opt-in flag, requires MongoDB authentication on boot, runs the container read-only, and replaces the wildcard CORS policy with an allowlist. Deployments still running an affected version should close the exposed ports immediately, rotate every LLM provider key that was ever present in the container's environment, and audit the memory store for injected entries — a redeploy on the patched version does not, by itself, undo prior memory poisoning. The broader lesson holds for any MCP server acting as a single point of tool access for an agent platform: an endpoint that can invoke shell execution, database writes, and credential-bearing environment reads is not an internal implementation detail, it is the platform's entire security boundary, and it needs to be treated like one from the first commit rather than patched into existence after disclosure.
