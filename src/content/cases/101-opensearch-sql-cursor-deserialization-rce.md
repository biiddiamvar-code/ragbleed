---
caseId: "101"
title: "OpenSearch's SQL plugin deserialized an authenticated caller's cursor straight into code execution"
filed: "2026-09-03"
filedDisplay: "03 Sep 2026"
firstObserved: "31 Aug 2026"
severity: high
category: "Embedding / vector store exposure"
status: "Patched"
affectedSystems: "OpenSearch SQL plugin, self-managed (v2.8 through v3.6); Amazon OpenSearch Service (v2.9 through v3.5)"
cve: "CVE-2026-83497"
readTime: "4 min read"
related: ["037", "039", "044"]
---

## Summary

OpenSearch is a common backend for RAG retrieval through its k-NN plugin, and production deployments routinely run that plugin on the same cluster as OpenSearch's SQL plugin, which ships enabled by default and is used for analytics and ad hoc querying against the same indices. AWS disclosed CVE-2026-83497 on 31 August 2026: the SQL plugin's cursor-pagination feature deserialized a client-supplied token without restricting what it could contain, letting a remote, authenticated caller holding nothing more than basic read/search permissions execute arbitrary code on the node. A credential scoped only to query a RAG system's vector index carries exactly that permission level — read/search — on most deployments.

## What was observed

The SQL plugin lets clients page through large result sets by round-tripping an opaque `cursor` token: the server hands one back with a partial result set, and the client echoes it on the next request to resume where it left off. Per AWS's advisory, the plugin reconstructed that cursor's session state by deserializing the client-supplied value directly, with no restriction on which classes were eligible for deserialization — a classic CWE-502 unrestricted-deserialization flaw. A caller who substituted a crafted serialized object for a legitimate cursor could get the server to execute code as a side effect of rebuilding that object graph, with no privilege beyond the ability to issue a search query in the first place.

```
POST /_plugins/_sql?format=jdbc
{"cursor": "<attacker-supplied serialized object, not a real pagination token>"}
# server deserializes the cursor value unconditionally -> CWE-502 -> code execution
```

No sandboxing, class allowlist, or additional authorization gate sat between the incoming cursor value and deserialization. The flaw affected the open-source SQL plugin from v2.8 through v3.6, and Amazon OpenSearch Service's managed offering from v2.9 through v3.5 — meaning it had been present across roughly two major release lines before AWS's bulletin.

## Mitigation

Self-managed OpenSearch should upgrade to 2.19.6 or 3.7 or later; Amazon OpenSearch Service customers should confirm the automatic service software update carrying the fix has applied to their domain. Where the SQL plugin isn't in active use, disable it or restrict the `plugins/sql` endpoint to trusted internal callers rather than leaving it reachable to every credential on the cluster. The broader lesson: a service account scoped down to "read/search only" against a RAG system's vector index is only as contained as the least-scrutinized feature bundled onto the same cluster — pagination, analytics, and debugging surfaces deserve the same authorization review as the vector search path they sit next to.
