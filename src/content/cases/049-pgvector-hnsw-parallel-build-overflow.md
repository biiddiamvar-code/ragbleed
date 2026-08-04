---
caseId: "049"
title: "An integer wraparound in pgvector's parallel HNSW index build let one relation's memory leak into another's"
filed: "2026-08-04"
filedDisplay: "04 Aug 2026"
firstObserved: "25 Feb 2026"
severity: low
category: "Embedding / vector store exposure"
status: "Patched"
affectedSystems: "pgvector, PostgreSQL extension (versions 0.6.0 through 0.8.1)"
cve: "CVE-2026-3172"
readTime: "4 min read"
related: ["012", "026", "039"]
---

## Summary

pgvector, the PostgreSQL extension most RAG stacks reach for when they want vector search without standing up a separate vector database, shipped a buffer overflow in the code path that builds HNSW indexes using parallel workers. An integer wraparound in that path let a database user with permission to create or reindex an HNSW index trigger memory corruption — either crashing the backend or pulling bytes belonging to unrelated relations into the index build. The bug lived in every release from 0.6.0 through 0.8.1, roughly two years of the extension's history.

## What was observed

HNSW (Hierarchical Navigable Small World) is pgvector's default recommendation for approximate nearest-neighbor search over embeddings, and building or rebuilding one over a large table is exactly the case parallel workers exist to speed up. Somewhere in the size and offset accounting that coordinates work across those parallel workers, a value wrapped around due to integer overflow, producing a buffer size that no longer matched the memory actually allocated for it.

```
# illustrative: parallel build tracks buffer size/offset across workers;
# an overflowed value here no longer bounds the actual allocation
```

Depending on how the resulting out-of-bounds access landed, the consequence was either a crashed backend process — an availability hit, recoverable on restart — or memory contents from other relations bleeding into the index build, a narrow but real information-disclosure path. The reporter (credited in the advisory as chungkn of OneMount Group) demonstrated both outcomes were reachable from the same root cause. Because the bug required only the ability to create or reindex an HNSW index with parallel workers enabled — an operation available to any database role with `CREATE INDEX` rights on the table, not just a superuser — this is reachable by an ordinary application-level database user in any deployment that lets one exist.

That access requirement is also what keeps this rated low rather than higher: the attacker needs a foothold that already includes index-creation privileges inside the Postgres instance, and the leaked memory contents aren't attacker-chosen — a wraparound produces whatever happens to sit at the corrupted offset, not a targeted read of a specific relation. That changes for multi-tenant or self-serve platforms built on shared Postgres instances where end users are handed enough privilege to create their own indexes; there, "requires CREATE INDEX" stops being much of a gate at all.

## Mitigation

Upgrade to pgvector 0.8.2 or later, which fixes the overflow. Until upgraded, avoid granting index-creation or reindex privileges on HNSW-backed tables to untrusted or lower-trust database roles, and be specifically cautious with any platform that exposes per-tenant index management on a shared Postgres instance — that pattern turns a privileged-access precondition into something closer to a tenant-boundary bypass. More broadly: index-build code paths get far less security scrutiny than query paths, on the assumption that only trusted operators run `CREATE INDEX` — an assumption that doesn't hold once a product lets end users manage their own embedding indexes.
