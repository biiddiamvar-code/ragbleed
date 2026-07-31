---
caseId: "040"
title: "Langflow's /api/v1/responses endpoint let any authenticated user execute another tenant's flow"
filed: "2026-07-31"
filedDisplay: "31 Jul 2026"
firstObserved: "19 Jun 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Langflow (< 1.9.1)"
cve: "CVE-2026-55255 (GHSA-qrpv-q767-xqq2); added to CISA KEV on 07 Jul 2026"
readTime: "5 min read"
related: ["008", "016", "038"]
---

## Summary

Langflow's flow-lookup helper, `get_flow_by_id_or_endpoint_name`, resolved a flow two different ways depending on what the caller supplied. Looked up by human-readable endpoint name, it correctly filtered on the requesting user's ID. Looked up by raw UUID, it queried the database directly and returned whatever flow matched, with no ownership check at all. The `/api/v1/responses` and `/api/v2/workflow` endpoints took a flow ID straight from the request body and passed it into this helper, so any authenticated user — including one holding only a low-privilege API key — could execute any other tenant's flow simply by supplying its UUID. Because Langflow flows routinely embed LLM provider keys, database credentials, and other integration secrets as node parameters, executing someone else's flow could expose those secrets and run up their compute bill. CISA added the flaw to its Known Exploited Vulnerabilities catalog on July 7, 2026, citing observed in-the-wild use.

## What was observed

The two lookup branches inside `get_flow_by_id_or_endpoint_name` diverged: the `endpoint_name` branch scoped its query with `Flow.user_id == uuid_user_id`, while the UUID branch called `session.get(Flow, flow_id)` and returned the row unconditionally. Any code path that accepted a flow identifier and forwarded it to this helper inherited the gap only if it happened to pass a UUID rather than a name — which the OpenAI-compatible `/api/v1/responses` endpoint always did, since callers there identify flows by ID in the `model` field.

```
# attacker holds a valid but unprivileged API key for the same Langflow instance
POST /api/v1/responses
{"model": "<victim's-flow-uuid>", "input_value": "...", "stream": false}
# helper resolves the UUID with no ownership check -> victim's flow runs,
# using whatever credentials and tool access are wired into its nodes
```

Because the endpoint returned a normal 200 with the flow's output rather than a 403 or 404, an attacker could enumerate flow IDs and silently run each one to see what came back. Researchers later observed operators chaining this IDOR with a separate unauthenticated remote-code-execution bug in Langflow's public-flow-build path (CVE-2026-33017) — using the IDOR for reconnaissance and credential harvesting, then the RCE for code execution on the same exposed instances.

## Mitigation

Upgrade to Langflow 1.9.1 or later, which normalizes the ownership check across both lookup branches, returns a uniform 404 for cross-user access (avoiding a 403-vs-404 existence oracle), and moves the `/api/v1/run*` routes to auth-aware dependencies as defense in depth. Internet-facing Langflow instances still on pre-1.9.1 builds should be treated as compromised and audited, given the CISA KEV listing and confirmed exploitation. More generally, object-level authorization has to be enforced at the point of every lookup path a resource can be reached through, not just the one an API was originally designed around — a second, later-added way to address the same object silently reopens whatever check the first path already had.
