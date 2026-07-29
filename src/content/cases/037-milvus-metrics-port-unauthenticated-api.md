---
caseId: "037"
title: "Milvus registered its full REST API on the metrics port with no authentication at all"
filed: "2026-07-29"
filedDisplay: "29 Jul 2026"
firstObserved: "11 Feb 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Milvus (all versions before 2.5.27; 2.6.0 through <2.6.10)"
cve: "CVE-2026-26190"
readTime: "4 min read"
related: ["013", "026", "019"]
---

## Summary

Milvus is a widely deployed open-source vector database used as the retrieval backend behind RAG pipelines at scale. Its metrics and management port, 9091 — a port operators commonly leave reachable for Prometheus scrapers and health checks — carried two independent authentication failures. A debug endpoint accepted a token that was trivially derivable from a well-known default configuration value, and, separately, the entire `/api/v1/*` REST surface was mounted on that same port with no authentication middleware whatsoever. Either gap alone was enough to reach full administrative compromise; together they made port 9091 a more dangerous target than Milvus's actual query API.

## What was observed

Milvus exposes a `/expr` debug endpoint intended for internal diagnostics, which evaluates caller-supplied expressions against the running process. Access was gated by a token, but that token was computed deterministically from `etcd.rootPath`, a configuration value nearly every deployment leaves at its default of `by-dev`. Anyone who knew the default derivation could compute a valid token without ever seeing the running instance's configuration, then use `/expr` to evaluate arbitrary internal expressions — reading MinIO secrets, etcd credentials, and stored user credential hashes directly out of process state.

```
# /expr debug endpoint
# token = derive(etcd.rootPath)   -- etcd.rootPath defaults to "by-dev" almost everywhere
# valid token computable offline, without touching the target instance
```

The second issue didn't require even that: the full `/api/v1/*` REST API — the same surface used for collection management, data manipulation, and user administration — was registered on port 9091 without any authentication check. A caller who could route a request to that port could create an admin user, dump data, or alter collections directly, independent of whatever authentication the primary Milvus query port enforced. The metrics port was, in effect, a second front door with no lock, sitting next to a well-guarded one.

> The management API and the monitoring API were meant to be different surfaces with different trust levels. Mounting one on the other's port erased that distinction.

## Mitigation

Upgrade to Milvus 2.5.27 or 2.6.10 or later, both of which remove the unauthenticated REST registration from the metrics port and fix the debug-token derivation. Independent of the patch, restrict network access to port 9091 to localhost or an internal monitoring subnet — it should never be reachable from outside the cluster's trust boundary — and change `etcd.rootPath` away from its `by-dev` default. The general failure worth carrying forward: a monitoring or metrics port is not inherently low-risk just because its intended purpose is observability, and any port that shares a process with your primary service deserves the same authentication scrutiny as the service's main entry point, not less.
