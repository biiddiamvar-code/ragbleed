---
caseId: "013"
title: "AnythingLLM's setup-status endpoint handed out the vector database's API key"
filed: "2026-01-31"
filedDisplay: "31 Jan 2026"
firstObserved: "28 Jan 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "AnythingLLM (Qdrant-backed deployments with API key configured)"
cve: "CVE-2026-24477"
readTime: "4 min read"
related: ["007", "003", "011"]
---

## Summary

When AnythingLLM is configured to use Qdrant as its vector store with an API key, that key is meant to be a server-side secret protecting read and write access to every document embedding in the knowledge base. A status-check endpoint, meant only to report whether setup had completed, returned that key in plain text to anyone who asked — no login required.

## What was observed

`/api/setup-complete` exists to answer one question: has this AnythingLLM instance finished its initial configuration. That's the kind of endpoint applications often leave unauthenticated on purpose, since knowing "yes, setup is done" isn't sensitive by itself. The problem was in what else the response included: the full configuration object, unfiltered, which on Qdrant-backed instances contains the `QdrantApiKey` field in plain text.

```
GET /api/setup-complete
# response includes full config, unauthenticated
{
  "vectorDB": "qdrant",
  "QdrantApiKey": "<plaintext key>",
  ...
}
```

Qdrant's API key isn't a convenience credential — it's the boundary between "this vector database belongs to this application" and "anyone who has this string can read, write, or delete anything in it." Once exposed, an attacker has direct access to the underlying Qdrant instance itself, entirely outside AnythingLLM's own access controls: every embedded document in the knowledge base becomes readable, and because Qdrant's write access came with the same key, writable and deletable too.

That second half matters as much as the leak itself. A key this broad doesn't just disclose data once — it hands over standing control of the store that every RAG query in the application depends on, which is a strictly worse position than a one-time information leak.

## Mitigation

Upgrade to the patched AnythingLLM release, which stops returning vector-database credentials through the setup-status endpoint. If your instance has ever run a vulnerable version with Qdrant configured, rotate the Qdrant API key — a version upgrade doesn't invalidate a key that was already exposed. More generally, treat any "is setup complete" or health-check style endpoint as a candidate for accidentally serialize-everything responses; these routes get far less security review than login-gated ones precisely because they're assumed to be low-stakes.
