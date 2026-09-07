---
caseId: "108"
title: "Onyx copied one user's OAuth token into a shared config row any teammate's MCP call could read back out"
filed: "2026-09-07"
filedDisplay: "07 Sep 2026"
firstObserved: "17 Aug 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Onyx (open-source AI platform), MCP integration endpoints GET /api/mcp/servers and GET /api/mcp/servers/persona/{persona_id} (< 3.1.10; >= 3.2.0, < 3.2.14; >= 3.3.0-beta.0, < 4.0.0)"
cve: "CVE-2026-71424 (GHSA-q62f-rv3h-f822)"
readTime: "4 min read"
related: ["016", "038", "074"]
---

## Summary

Onyx is an open-source AI platform that lets users connect Model Context Protocol (MCP) servers, including servers that require a per-user OAuth authorization. A flaw in how Onyx stored those tokens caused one user's OAuth Authorization header to be readable by any other user on the same instance holding only the platform's default access role. The root cause was architectural, not a missing permission check on a single endpoint: per-user token data was written into a shared, server-scoped configuration row instead of a row scoped to the individual user who authorized it, and the endpoint returning that row to end users never distinguished whose token it currently held.

## What was observed

Onyx's MCP feature lets a user connect a personal MCP server gated behind that user's own OAuth session — a connector to a service that only that user should be able to reach. The backend functions responsible for persisting a completed OAuth flow, `OnyxTokenStorage.set_tokens` and `OnyxTokenStorage.set_client_info` in `backend/onyx/server/features/mcp/api.py`, wrote the resulting token into a shared `MCPConnectionConfig` database row tied to the MCP server definition itself, rather than to the user who had just authorized it.

That shared row was then exposed through `GET /api/mcp/servers` and `GET /api/mcp/servers/persona/{persona_id}` — both reachable by any authenticated user with the platform's default `BASIC_ACCESS` role. The function that serializes the row for the API response, `_db_mcp_server_to_api_mcp_server`, copied `auth_template.headers` — which by that point held whichever user's OAuth Authorization header had most recently been written to the shared row — straight into the response body.

```
# illustrative — per-user tokens landing in a shared field
OnyxTokenStorage.set_tokens(user_a_token)
    -> MCPConnectionConfig.auth_template.headers   # one shared row, not scoped per user

GET /api/mcp/servers                                # any BASIC_ACCESS caller
    -> _db_mcp_server_to_api_mcp_server(row)
    -> returns auth_template.headers                # whichever token is currently stored
```

Any low-privileged user calling either endpoint received another user's live OAuth bearer token, with no ownership check applied anywhere along the path. Whoever received that token could replay it against whatever service the connected MCP server fronted, inheriting the original user's authorization there — a direct route from "logged-in chat user" to "holder of a colleague's external credentials," reached entirely through a feature built to let individuals connect their own tools.

## Mitigation

Upgrade to Onyx 3.1.10, 3.2.14, or 4.0.0, all of which scope per-user MCP OAuth tokens to the user who authorized them instead of to the shared server configuration. Deployments that can't upgrade immediately should treat any MCP connector configured with per-user OAuth as exposed to every authenticated user on the instance and rotate credentials on the connected services once patched. The broader lesson repeats what this database has already logged against other multi-tenant MCP integrations (cases 016, 038, 074): a credential store keyed by "which server" instead of "which user" leaks across users the first time two people configure the same connector.
