---
caseId: "131"
title: "Open WebUI's built-in knowledge tool passed an access filter that eleven of fifteen vector backends silently ignored"
filed: "2026-09-23"
filedDisplay: "23 Sep 2026"
firstObserved: "09 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (>=0.7.0, <0.11.1), built-in knowledge search tool on a non-default vector backend (both Qdrant clients, Elasticsearch, OpenSearch, both Milvus clients, openGauss, Oracle 23ai, Pinecone, S3 Vectors, or Weaviate)"
cve: "CVE-2026-87017 (GHSA-pcvc-8vrv-8q6w)"
readTime: "4 min read"
related: ["079", "082", "065"]
---

## Summary

Open WebUI's built-in knowledge search tool works out which knowledge bases a calling user may read and passes that list to the vector store as a search filter, treating the filter as the only access check on the path. Each shipped vector client exposes two methods that look interchangeable from the calling side — `search` and `query` — but only `query` actually applied the filter. Eleven of the fifteen shipped backends ignored it on `search`, the method the knowledge tool uses, so a tool call returned matches drawn from every knowledge base in the shared collection rather than only the ones the caller owned. Fixed in 0.11.1.

## What was observed

The knowledge tool's access model delegated entirely to a parameter it handed downstream: it resolved the caller's readable knowledge base IDs correctly, passed them as a filter argument into the vector client's `search` method, and then trusted whatever came back without rechecking it — the reasonable assumption being that a filter handed to a vector store gets applied. That assumption held for the default backend, Chroma, and for pgvector, MariaDB, and Valkey. It did not hold for the other eleven shipped clients, including both Qdrant integrations, Elasticsearch, OpenSearch, both Milvus clients, Weaviate, Pinecone, S3 Vectors, openGauss, and Oracle 23ai. Each of those declared a `filter` parameter on its `search` method's signature and never referenced it inside the method body, while their sibling `query` method, called elsewhere in the codebase, did apply an equivalent filter — which is why the gap never surfaced as a functional bug during normal use.

```
# knowledge tool call, caller can read only kb-allowed
search(filter={"knowledge_base_id": {"$in": ["kb-allowed"]}})
# affected backends: returns entries from kb-allowed AND kb-secret
# unaffected backends (chroma, pgvector, mariadb, valkey): returns kb-allowed only
```

The exposure was bounded by how Open WebUI structures its collections. The affected collection stores one entry per knowledge base, holding that knowledge base's name and description as searchable text — not its documents, which live in separate per-knowledge-base collections reached through a different, correctly-scoped call. So the practical loss was enumeration: a caller with tool-use access could learn the identifiers, names, and descriptions of knowledge bases never shared with them, and could vary the query to enumerate the full set. Where a name or description itself named a customer, a project, or an investigation, that was the disclosure. No document text and no write access came through this path. Because the default backend was unaffected, the vulnerability's population was operators who had deliberately moved off Chroma to an external vector store — in practice, the larger production deployments the built-in knowledge feature is meant to scale to.

## Mitigation

Upgrade to Open WebUI 0.11.1 or later, which extends every affected backend's filter builder to express the set-membership form the knowledge tool sends, and rejects a filter it cannot honor rather than silently dropping it. No configuration change is required beyond the upgrade, and Chroma, pgvector, MariaDB, and Valkey deployments were never exposed. The recurring lesson across this class of bug is that a shared interface with two methods differing only in whether they respect a parameter is a trap for exactly this kind of silent regression — the fix note for each affected client now applies the filter as part of the same query construction the collection-scoping already used, rather than leaving it as a separately-honored option.
