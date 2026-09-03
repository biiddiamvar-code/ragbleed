---
caseId: "100"
title: "A second unauthenticated endpoint on Milvus's metrics port let anyone kill its worker processes"
filed: "2026-09-03"
filedDisplay: "03 Sep 2026"
firstObserved: "05 Aug 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "Milvus (through 2.6.22; also 3.0.0)"
cve: "CVE-2026-69111"
readTime: "4 min read"
related: ["037", "039", "019"]
---

## Summary

In July 2026, Milvus shipped fixes for CVE-2026-26190 (case 037): its metrics and management port, 9091, had been serving the entire `/api/v1/*` REST surface with no authentication at all, alongside a debug endpoint whose access token was trivially derivable. The 2.5.27 and 2.6.10 releases closed both holes. A month later, a researcher found that the same port still exposed an unauthenticated `/management/stop` route the earlier fix hadn't touched — one that let anyone with network access to port 9091 terminate any of Milvus's core service components with a single unauthenticated HTTP request.

## What was observed

The `/management/stop` endpoint accepts a `role` query parameter identifying which service component to shut down — `proxy`, `datanode`, or `querynode` — and calls that component's stop routine directly. It sits outside the authentication middleware that governs the rest of Milvus's REST API, so it never checks whether the caller has any credentials at all, even on deployments where authentication is turned on for the primary gRPC and HTTP ports.

```
# GET /management/stop?role=proxy   -- no auth header required
# handler resolves "role" and calls that component's Stop() directly,
# bypassing the REST auth middleware entirely
```

Because Milvus's proxy, data nodes, and query nodes are the components that actually serve reads and writes, stopping any one of them on a production cluster halts ingestion or search for every tenant sharing it — no credentials, no privileged access, and no interaction beyond one crafted request. The endpoint's existence alongside the just-patched `/api/v1/*` gap shows the earlier fix addressed one specific unauthenticated surface on port 9091 without establishing that every route on that port needed the same scrutiny.

> Milvus's own CVSS scoring puts this at 7.5–8.7. We rate it medium: unlike case 037, nothing here exposes data, credentials, or write access — the entire impact is that a component gets shut down and, presumably, restarted by its orchestrator. That's real disruption, not compromise, and the rubric this site uses weights confidentiality and integrity impact more heavily than availability-only bugs.

## Mitigation

Upgrade to the Milvus release incorporating upstream fixes from pull requests #49847 and #51573 — check the project's release notes or security advisory for the exact version number, which wasn't stated consistently across public reporting at the time of writing. Independent of the patch, the guidance from case 037 still applies and evidently needs restating: port 9091 should never be reachable from outside a cluster's trust boundary, restricted to localhost or an internal monitoring subnet only. When a vendor patches "the unauthenticated management port" as a single incident, treat that as a prompt to audit every route registered on that port individually, not evidence the port is now safe as a whole.
