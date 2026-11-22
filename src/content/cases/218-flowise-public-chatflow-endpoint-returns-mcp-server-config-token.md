---
caseId: "218"
title: "Flowise's public chatflow endpoint spread the whole chatflow record into its response, returning the MCP server token that the sanitizer never looked at"
filed: "2026-11-22"
filedDisplay: "22 Nov 2026"
firstObserved: "17 Nov 2026"
severity: medium
category: "Disclosure failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Flowise (FlowiseAI/Flowise, 3.1.3 through 3.1.4), chatflows marked public with MCP server exposure configured; repository archived, no fixed release"
cve: "CVE-2026-130796 (VulnCheck advisory; CWE-212, CVSS 4.0 8.8, CVSS 3.1 8.2)"
readTime: "4 min read"
related: ["007", "212", "165"]
---

## Summary

Flowise's unauthenticated `GET /api/v1/public-chatflows/:id` handler returned the full stored chatflow record for any chatflow marked public, sanitizing only the `flowData` field. The record's `mcpServerConfig` column, which holds the token that authenticates calls to the chatflow's MCP endpoint, passed through untouched. VulnCheck reports that the token could then be presented to `POST /api/v1/mcp/:chatflowId` to invoke the chatflow outside its API key protection, on the owner's model quota. The project reached end of life in August 2026 and no fix has been published.

## What was observed

VulnCheck published the advisory and CVE-2026-130796 on 17 Nov 2026, crediting George Chen, and lists Flowise 3.1.3 through 3.1.4 as affected. The advisory links three locations in the source tree at commit `a65f81b`, which were reviewed for this case.

In `packages/server/src/controllers/chatflows/index.ts`, the public handler loaded the chatflow by ID, checked only `chatflow.isPublic`, and responded with the entity spread into a new object, replacing a single field with a sanitized copy:

```
// getSinglePublicChatflow (abridged from the referenced commit)
const chatflow = await chatflowsService.getChatflowById(req.params.id)
if (chatflow.isPublic)
    return res.json({ ...chatflow, flowData: sanitizeFlowDataForPublicEndpoint(chatflow.flowData) })
// every other column, including mcpServerConfig, is copied as stored
```

In `packages/server/src/database/entities/ChatFlow.ts`, `mcpServerConfig` was declared as a nullable `text` column with no `select: false`. The same entity already applied `select: false` to `webhookSecret`, so the codebase had a mechanism for keeping a secret column out of default reads; the MCP column did not use it. The sanitizer that did run was scoped to the graph definition in `flowData`, which is where the earlier public-chatflow disclosure, CVE-2026-41278 (case 007), had leaked credentials. The MCP configuration lived outside that field and outside that fix.

The abuse path beyond disclosure, presenting the leaked token to the chatflow's MCP route, is described in the VulnCheck advisory. The token-comparison code in `packages/server/src/services/mcp-server/index.ts` could not be retrieved for this case, so how the route validates the token was not independently reviewed.

Severity is rated medium, below the CVSS 4.0 score of 8.8. The leak required no authentication, but it applied only to chatflows that were both marked public and configured for MCP exposure, and the token's documented reach was invocation of that same chatflow and consumption of its owner's quota, not access to the provider keys or other tenants' data.

## Mitigation

No patched Flowise release exists. The maintainers froze the codebase on 29 Jul 2026, archived the repository in August, and declared end of life on 31 Aug 2026; the sunset notice directs teams to fork. Operators still running Flowise should disable MCP server exposure on any public chatflow, rotate every MCP token that was configured on a chatflow while it was public, and review model-provider usage for unexplained invocations. Where a reverse proxy fronts the instance, strip `mcpServerConfig` from `/api/v1/public-chatflows/` responses or block that route if the embed does not need it. Teams maintaining a fork should mark the column `select: false` and replace the spread in the public handler with an explicit allowlist of fields.

A sanitizer that names the field it cleans is a denylist of one, and every column added after it ships is public by default.
