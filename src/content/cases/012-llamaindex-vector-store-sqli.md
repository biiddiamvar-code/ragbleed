---
caseId: "012"
title: "LlamaIndex let the model itself carry a SQL injection into the vector store"
filed: "2026-07-15"
filedDisplay: "15 Jul 2026"
firstObserved: "10 Jul 2026"
severity: high
category: "Embedding / vector store exposure"
status: "Patched"
affectedSystems: "LlamaIndex vector store integrations — ClickHouse, Couchbase, DeepLake, Jaguar, Lantern, Nile, OracleDB, SingleStoreDB (versions prior to 0.12.28)"
cve: "CVE-2025-1793 (GHSA-v3c8-3pr6-gr7p)"
readTime: "5 min read"
related: ["011", "005", "001"]
---

## Summary

Several of LlamaIndex's vector store integrations built their delete and filter operations by inserting values directly into a query string, without sanitizing them first. In a normal web application, that's a standard SQL injection bug reachable by a user typing into a form. In a RAG pipeline, the same bug is reachable by anyone who can influence what the model says — because the model, not the user, is what actually writes the query.

## What was observed

RAG systems commonly let the LLM decide how to filter or delete entries in a vector store based on conversational context — a user asks to "remove the old pricing document," and the model translates that into a structured delete call against the vector store. Several LlamaIndex vector store integrations passed the resulting values straight into a query string. `vector_store.delete()` on the affected backends performed no escaping before that string reached the database.

```
# affected pattern, simplified across integrations
query = f"DELETE FROM {table} WHERE doc_id = '{doc_id}'"
# doc_id can originate from LLM-generated output, not just direct user input
```

This class of bug isn't the interesting part on its own — string-built SQL has been a known mistake for decades. What makes it worth filing here is who's allowed to supply `doc_id` in a RAG context: not a user typing directly into a query field, but an LLM composing a value based on a conversation that itself may include retrieved content or injected instructions. A harmless-looking user message can steer the model into generating a value that happens to be a SQL payload, and the application layer never sees anything unusual — it only sees the model doing what it's supposed to do, decide what to query.

Eight separate vector store integrations shared the same underlying pattern, with inconsistent fixes: some (OracleDB) moved to a strict character allowlist, others (Jaguar) used a narrower blacklist — a reminder that patching the same bug class across many integrations doesn't guarantee uniformly rigorous fixes.

## Mitigation

Upgrade to LlamaIndex 0.12.28 or later, which adds sanitization across all eight affected vector store integrations. Because the fixes vary in strictness between integrations, don't treat "patched" as equally strong everywhere — if you're on an integration that used a blacklist rather than an allowlist, budget extra scrutiny for edge cases. More broadly: any value an LLM is allowed to compose and hand to a downstream system — a database query, a file path, a shell argument — needs the same input validation you'd apply to a value a user typed directly, because from the database's perspective, that's exactly what it is.
