---
caseId: "166"
title: "Langflow's project-scoped MCP resources/read handler checked the project ID but not the requested resource URI, returning other users' flow files"
filed: "2026-10-13"
filedDisplay: "13 Oct 2026"
firstObserved: "22 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Langflow (langflow, >=1.6.8, <=1.9.0; fixed in 1.9.1)"
cve: "CVE-2026-105699 (GHSA-4hmc-cfm3-w43c, CWE-639, CVSS 4.0 7.1); the GitHub advisory page lists no CVE ID"
readTime: "3 min read"
related: ["040", "155", "164"]
---

## Summary

Langflow's project-scoped MCP transport authorized a caller against the project ID in the connection URL and then served `resources/read` requests without checking the requested URI. An authenticated user with access to any project-scoped MCP endpoint could name another user's flow-backed file and receive its contents. The flaw was fixed in Langflow 1.9.1.

## What was observed

The `resources/read` handler passed the client-supplied URI to `handle_read_resource`. That function parsed a `flow_id` and a filename from the URI and called `storage_service.get_file`. At no point did it confirm that the flow belonged to the authenticated user or to the project in the connection. The advisory classifies the flaw as authorization bypass through a user-controlled key (CWE-639).

```
# MCP connection: /api/v1/mcp/project/<own_project_id>   (access check passes)
# resources/read  uri = <other user's flow_id>/<filename>
# parse flow_id + filename -> storage_service.get_file(...)   (no ownership check)
# file contents returned to the caller
```

The global `handle_list_resources` and `handle_list_tools` helpers listed items across all users, which supplied the flow identifiers an attacker needed. Exposed material was the contents of uploaded documents, CSVs, JSON and other flow storage files. In a RAG deployment those files are typically the source documents behind a flow. The advisory reports no integrity or availability impact; stored flows and files were not modified.

The fix in 1.9.1 (pull request #12818) requires an authenticated user for resource reads and resolves the URI to a flow owned by that user, and within the project for project-scoped servers. It rejects filenames containing `..`, `/` or `\`, applies the same containment check in the storage layer, and scopes global resource and tool listing to the current user. The advisory page and the aggregated CVE record disagree on whether 1.9.0 or 1.9.1 is the upper bound of the affected range; this entry follows the advisory's `<=1.9.0`. The CVE record was published on 5 Oct 2026, after the advisory.

## Mitigation

Upgrade Langflow to 1.9.1 or later. The advisory lists no workarounds. Operators who cannot upgrade should restrict who can reach project-scoped MCP endpoints and treat any file stored in a flow as readable by those users. A handler that checks access to a container but then accepts a fully qualified identifier for the contents must re-derive ownership from that identifier.
