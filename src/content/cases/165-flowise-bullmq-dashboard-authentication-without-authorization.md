---
caseId: "165"
title: "Flowise mounted its BullMQ admin dashboard behind a token check with no role or workspace check, exposing every tenant's queued jobs to any logged-in user"
filed: "2026-10-13"
filedDisplay: "13 Oct 2026"
firstObserved: "26 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "Flowise (FlowiseAI/Flowise, 3.1.4 and earlier) in queue mode with ENABLE_BULLMQ_DASHBOARD=true, non-cloud"
cve: "CVE-2026-100608 (GHSA-rpcc-gw54-mfgx, CWE-862, CVSS 4.0 8.7)"
readTime: "3 min read"
related: ["007", "040", "041"]
---

## Summary

Flowise in queue mode can mount the Bull-Board dashboard for its BullMQ job queues at `/admin/queues`. The route verified that the caller held a valid JWT and performed no role, permission or workspace check. Any authenticated user, including the lowest-privileged member of any tenant, could open the dashboard and read job payloads for the whole instance. No patched version was listed in the advisory at the time of writing.

## What was observed

The vulnerable configuration was `MODE=queue` with `ENABLE_BULLMQ_DASHBOARD=true` on a non-cloud deployment. In that configuration the `/admin/queues` mount was guarded only by `verifyTokenForBullMQDashboard`, a middleware that validated the token and nothing else. The mount also sat outside `/api/v1/*`, so the global API permission gate did not apply to it. The reporter attributes the gap to a January 2026 change that added authentication to the route without adding authorization.

```
# GET /admin/queues     (Authorization: valid JWT, any role, any workspace)
# middleware: token valid? -> yes -> route served
# no check of role, permission, organization or workspace
```

Job payloads in a Flowise queue carry the content of the work being run. According to the advisory, the dashboard exposed chat inputs, `overrideConfig` values, chatflow graph definitions, credential IDs, uploaded files and organization and workspace identifiers across all tenants. The dashboard's write actions (retry, remove, promote, clean) were also reachable, so a low-privileged user could alter other tenants' queued work.

The advisory states that the reporter's proof of concept simulated the middleware and was not run against a live deployment; the impact has not been confirmed end to end. The vendor-neutral score of 8.7 (CVSS 4.0) rates the flaw as high. This catalogue rates it medium because exploitation requires a non-default queue-mode deployment with the dashboard explicitly enabled, and a valid account on the instance.

## Mitigation

No fixed release was listed. Unset `ENABLE_BULLMQ_DASHBOARD`, or set it to any value other than `true`; queue mode continues to operate without it. Where the dashboard is required, restrict `/admin/queues` at the reverse proxy or network layer to operator addresses. Audit existing queued and retained job data for credentials and prompts that tenants should not share. An operational console mounted outside the API router inherits none of the router's authorization; each such mount needs its own permission check.
