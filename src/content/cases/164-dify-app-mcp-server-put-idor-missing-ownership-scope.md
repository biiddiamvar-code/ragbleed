---
caseId: "164"
title: "Dify's app MCP server update endpoint loaded records by client-supplied ID without ownership scoping"
filed: "2026-10-12"
filedDisplay: "12 Oct 2026"
firstObserved: "05 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Dify (langgenius/dify, all versions before 1.16.0)"
cve: "CVE-2026-105761 (GHSA-ccrj-frp2-c945, CWE-639, CVSS 3.1 7.1)"
readTime: "3 min read"
related: ["008", "040", "046"]
---

## Summary

The `PUT /console/api/apps/<app_id>/server` endpoint in Dify loaded an MCP server record using an ID supplied by the client and did not verify that the record belonged to the app and tenant named in the URL. An authenticated workspace member could therefore modify the status and parameters of another application's MCP server. The flaw was fixed in Dify 1.16.0.

## What was observed

Dify can expose an application as an MCP server. The update handler, `AppMCPServerController.put()` in `api/controllers/console/app/mcp_server.py`, accepted a server ID in the request and fetched the matching `AppMCPServer` row by that ID alone. The `app_id` in the path was not used to constrain the query. The CVE record classifies the flaw as authorization bypass through a user-controlled key (CWE-639).

```
# PUT /console/api/apps/<own_app_id>/server
# body carries the server id of an MCP server belonging to another app
# lookup: AppMCPServer where id == body.id   (no app_id / tenant_id filter)
# the foreign record's status and parameters are updated
```

The impact recorded in the advisory is integrity-focused: a caller could change another application's MCP server status and parameters, which could disable the service or alter how it behaved. The CVSS 3.1 vector (7.1, `C:N/I:H/A:L`) reflects no confidentiality impact. The advisory text reviewed describes "another application" and does not state whether the affected record could belong to a different workspace; the cross-tenant reach was not independently verified. The upstream fix, pull request #38177, scopes nested resource lookups by owner references, so a record is queried with its parent app and tenant identifiers rather than by its own ID. CISA's SSVC data lists exploitation as none and the flaw is not in the KEV catalog.

## Mitigation

Upgrade Dify to 1.16.0 or later. Workspaces that cannot upgrade immediately should limit which members hold editor or admin roles on apps with MCP servers enabled, and review MCP server configurations for unexpected changes. The pull request also notes that review comments flagged other nested lookups, such as dataset segments, that did not yet enforce nested scope at review time. A route that nests a child resource under a parent must apply the parent's identifiers in the query, not only in the URL.
