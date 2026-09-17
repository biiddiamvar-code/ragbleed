---
caseId: "125"
title: "A relative webhook target let LangGraph Server requests reach another tenant's threads without authentication"
filed: "2026-09-17"
filedDisplay: "17 Sep 2026"
firstObserved: "19 Aug 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "langgraph-api / LangGraph Server (Agent Server runtime, including the LangGraph Platform Helm chart), all versions before 0.10.0"
cve: "CVE-2026-55235 (GHSA-2c9q-c2q9-qgqv)"
readTime: "4 min read"
related: ["076", "016", "108"]
---

## Summary

LangGraph Server lets a run or cron job specify a webhook target to notify when work completes. When that target was a relative URL rather than an absolute one, the server delivered it by routing the request back into its own process over an in-process loopback transport — a path the authentication middleware treated as internal and did not authenticate. In deployments that scope threads and runs by owner, a request tied to one user could ride that unauthenticated internal path into another user's thread, creating a run on it or modifying its state, even though the equivalent direct external request was correctly denied. Fixed in `langgraph-api` 0.10.0.

## What was observed

The bug lived at the boundary between two reasonable-sounding design decisions: webhooks can be relative URLs (convenient for routes hosted on the same server), and in-process requests are treated as trusted internal traffic (avoiding pointless self-authentication). Combined, they meant a webhook target didn't have to reach an external endpoint at all — it could resolve to the server's own API surface, and arrive there through a code path that skipped the checks an ordinary HTTP client would have hit.

```
# illustrative: creating a run with a relative webhook target
POST /threads/{thread_id}/runs
{ "webhook": "/threads/other-users-thread-id/runs" }
# delivery routes through an in-process ASGI transport, not the network —
# the auth middleware treats it as internal and does not check it
```

The delivered webhook request then executed against the server's own thread and run routes, carrying whatever authorization context the in-process transport implicitly granted rather than the requesting user's own scope. Because per-user thread isolation in LangGraph Server deployments is typically enforced at exactly that authorization layer — the layer this path bypassed — a webhook could be used to create a run on, or modify the state of, a thread the requesting user did not own, and limited metadata from the target thread could be pulled into the resulting run record. The vendor reported no evidence of in-the-wild exploitation.

## Mitigation

Upgrade to `langgraph-api` 0.10.0 or later, where the `webhooks.url.disable_loopback` policy now defaults to enabled: relative webhook targets, localhost-style hostnames, loopback address ranges, and hostnames that resolve into loopback space are all denied by default. Deployments that legitimately deliver webhooks to a route on the same process can opt back in via `webhooks.url.disable_loopback: false`, but only for routes they control, since delivery to them remains unauthenticated. This site rates the mechanism high against the advisory's own CVSS 5.9 (medium): the score discounts for requiring an authenticated caller and non-trivial setup (`AC:H`, `PR:L`), but the resulting primitive — creating or modifying another tenant's thread state from inside a multi-tenant deployment — is exactly the cross-tenant outcome this site treats as high regardless of how many steps it takes to reach. The general lesson: "internal" and "authenticated" are not the same property, and a transport that skips auth because it assumes only trusted code can reach it needs to verify that assumption stays true even when the target of a request is attacker-influenced.
