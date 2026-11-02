---
caseId: "191"
title: "Flexible GraphRAG's FalkorDB adapter escaped quotes before backslashes, letting LLM-extracted entity IDs inject Cypher"
filed: "2026-11-02"
filedDisplay: "02 Nov 2026"
firstObserved: "03 Oct 2026"
severity: low
category: "Data poisoning (ingestion-time)"
status: "Patched"
affectedSystems: "flexible-graphrag (pip, >=0.6.0, <0.8.2), GRAPH_BACKEND=langchain with GRAPH_DB=falkordb"
cve: "CVE-2026-114510 (GHSA-vqrg-773h-4wxc, CWE-116 / CWE-943, CVSS 3.1 7.1)"
readTime: "4 min read"
related: ["005", "012", "118"]
---

## Summary

Flexible GraphRAG's FalkorDB adapter built Cypher queries by string interpolation and sanitised values with an `_escape()` helper that applied its replacements in the wrong order. A quote character in an entity ID survived escaping and closed the string literal early. Because entity IDs and types are produced by an LLM reading ingested documents, a crafted document was sufficient to reach the query. The flaw was fixed in version 0.8.2.

## What was observed

In versions 0.6.0 through 0.8.1, `FalkorDBAdapter.add_graph_documents` wrote extracted entities and relationships to the graph with Cypher assembled from formatted strings. The `_escape()` helper first prefixed single quotes with a backslash, then doubled backslashes. The second step doubled the backslash the first step had just inserted, which left the quote unescaped. Node and relationship type names, inserted into backtick-quoted positions, were not escaped at all.

```
# document text steers the extraction model to emit this entity ID:
#   Acme' } ) DETACH DELETE ... //
# _escape(): quote -> \'   then   backslash -> \\   =>   \\'
# the quote is now live; the string literal ends and attacker Cypher follows
```

The input path ran through the extraction model rather than through an HTTP parameter. An attacker who could place text in any ingested source controlled what the model emitted as an entity ID, and the adapter treated that output as trusted. The advisory reports that a single injected clause could delete every node and relationship in the graph. Reading or altering other data was possible where the calling code returned query results to a user or an LLM.

The issue applied only when `GRAPH_BACKEND=langchain` and `GRAPH_DB=falkordb` were both set. The LlamaIndex FalkorDB store was not affected. The advisory rates the issue high (CVSS 3.1 of 7.1). It is rated low here: the vulnerable path required a non-default backend pairing, and the demonstrated impact was integrity loss in a derived graph rather than exposure of private or cross-tenant data.

## Mitigation

Upgrade flexible-graphrag to 0.8.2 or later. That release passes values as query parameters and strips backticks from labels, relationship types, and property keys. Deployments that cannot upgrade immediately can switch to `GRAPH_BACKEND=llamaindex` with FalkorDB, or use a different graph database.

Output from an extraction model is attacker-influenced data whenever the source documents are. It belongs in query parameters, never in query text.
