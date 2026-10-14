---
caseId: "167"
title: "Langflow's deprecated build/vertices routes loaded flows by primary key without an owner filter, letting any authenticated user execute another user's vertices"
filed: "2026-10-14"
filedDisplay: "14 Oct 2026"
firstObserved: "28 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "langflow (>=1.0.0, <1.10.1); langflow-base (<0.10.1)"
cve: "CVE-2026-105698 (GHSA-gh98-4phw-6fmw, CWE-639 / CWE-862, CVSS 3.1 5.4)"
readTime: "3 min read"
related: ["040", "166", "155"]
---

## Summary

Two deprecated Langflow chat API routes accepted a flow UUID in the URL and built the corresponding graph without confirming the caller owned the flow. A caller who knew another user's flow ID could list its vertices and execute them, receiving their outputs. The flaw was fixed in langflow 1.10.1 and langflow-base 0.10.1.

## What was observed

The affected routes were `POST /api/v1/build/{flow_id}/vertices` and `POST /api/v1/build/{flow_id}/vertices/{vertex_id}`. They were hidden from the OpenAPI schema and no longer used by the UI, but remained reachable. The graph loader performed a primary-key lookup with no owner filter. Through 1.7.1 the routes required no authentication at all; from 1.7.2 authentication was added, but not an ownership check.

```
# POST /api/v1/build/<victim_flow_id>/vertices           (authenticated as any user)
# loader: SELECT flow WHERE id = <victim_flow_id>         (no owner predicate)
# response: vertex IDs and component types of the victim's graph
# POST .../vertices/<vertex_id> -> vertex executes, output returned
```

The advisory rates confidentiality and integrity impact as low. Exposed material was vertex identifiers, component types, and the outputs of built vertices, which include hardcoded configuration values. Execution of the victim's nodes could trigger their configured side effects, and build records were written under the victim's flow ID. Global variables and stored credentials were not exposed, the stored flow could not be modified, and availability was unaffected. Exploitation required a valid account and the target flow UUID; the advisory notes that blind enumeration of random UUIDs is impractical.

The fix in 1.10.1 (pull request #13153) switched the handlers to an owner-scoped query that permits owners and public flows, returns 404 for inaccessible flows, and checks execute permission before building or caching a graph. Later releases extended the change: 1.11.2 covered the sibling stream route, and 1.12.0 made all three deprecated routes owner-only. This entry follows the advisory's CVSS rating; the severity here is medium because the default multi-user configuration is affected and flow outputs can carry embedded configuration, while the UUID prerequisite limits reach.

## Mitigation

Upgrade langflow to 1.10.1 or later and langflow-base to 0.10.1 or later; 1.12.0 or later closes the sibling routes fully. Where upgrading is delayed, block `POST /api/v1/build/*/vertices`, `POST /api/v1/build/*/vertices/*` and `GET /api/v1/build/*/*/stream` at the reverse proxy. Deprecated routes hidden from the schema remain attack surface until they are removed or covered by the same authorization checks as their replacements.
