---
caseId: "028"
title: "LiteLLM's MCP test endpoints spawned attacker-supplied commands with no admin check"
filed: "2026-07-25"
filedDisplay: "25 Jul 2026"
firstObserved: "08 Jun 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LiteLLM proxy/AI gateway, MCP test endpoints (>=1.74.2, <1.83.7); unauthenticated when chained with Starlette <=1.0.0 (CVE-2026-48710)"
cve: "CVE-2026-42271 (chainable with CVE-2026-48710, \"BadHost\")"
readTime: "5 min read"
related: ["014", "017", "018"]
---

## Summary

LiteLLM, an open-source AI gateway that many organizations put in front of every model provider they use, shipped two endpoints meant to let administrators preview an MCP server configuration before saving it. Those endpoints accepted a full stdio server configuration — including the literal command to run — and executed it as a subprocess on the proxy host, gated by nothing more than possession of any valid proxy API key. Chained with a separate authentication-bypass bug in the Starlette web framework LiteLLM depends on, the flaw became unauthenticated remote code execution, and CISA confirmed active exploitation before most deployments had patched.

## What was observed

`POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list` existed so an administrator could verify an MCP server would connect correctly before committing it to config. For a stdio-transport MCP server, "verify it connects" means "run the command." The endpoints accepted `command`, `args`, and `env` fields straight from the request body and spawned them as a subprocess with the privileges of the proxy process itself. The endpoint that actually persisted an MCP server configuration required the `PROXY_ADMIN` role; the two test endpoints did not — they checked only for a valid API key, a bar any authenticated proxy user clears.

```
# save endpoint: requires PROXY_ADMIN role
POST /mcp-rest/servers          -> role check enforced

# test endpoints: requires only a valid API key
POST /mcp-rest/test/connection  -> spawns request-body "command" as subprocess
POST /mcp-rest/test/tools/list  -> same
```

That gap turned a preview feature into RCE for any tenant or internal user holding a standard key, exposing model-provider credentials and every other secret the gateway held, and a pivot point into whatever infrastructure the gateway could reach. Researchers subsequently chained it with CVE-2026-48710, a Host-header validation bypass in Starlette ("BadHost") affecting the same dependency LiteLLM ships, to drop the API-key requirement entirely — turning the bug into remote code execution reachable from any network-connected host with no credentials at all. CISA added the base flaw to its Known Exploited Vulnerabilities catalog after confirming active exploitation in the wild.

> A feature built to let administrators safely preview a config before trusting it skipped the one check that made "preview" different from "execute."

## Mitigation

Upgrade LiteLLM to 1.83.7 or later, which brings the test endpoints in line with the save endpoint's `PROXY_ADMIN` requirement, and upgrade Starlette to 1.0.1 or later to close the chained bypass. Where immediate patching isn't possible, block the two test endpoints at the reverse proxy, restrict network access to trusted segments, and rotate any credentials the gateway held. The broader lesson: preview and test endpoints are still endpoints — if the action they perform is privileged when done through the primary interface, it needs the same privilege check when done through a secondary one, regardless of how transient or read-only the feature is meant to feel.
