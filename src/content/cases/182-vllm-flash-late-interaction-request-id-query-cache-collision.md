---
caseId: "182"
title: "vLLM keyed its flash late-interaction query-embedding cache on the caller's X-Request-Id, letting a second request overwrite another user's cached query"
filed: "2026-10-23"
filedDisplay: "23 Oct 2026"
firstObserved: "23 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vllm (PyPI, <0.30.0; confirmed on 0.25.1, lower bound not established; patched in 0.30.0)"
cve: "CVE-2026-105755 (GHSA-2phq-3phc-84px, CWE-639, CVSS 3.1 4.2)"
readTime: "3 min read"
related: ["151", "113", "137"]
---

## Summary

On vLLM's `/score` and `/rerank` endpoints with flash late interaction, the worker cached query embeddings under a key built from the client-supplied `X-Request-Id` header. A second request reusing the same header value overwrote the first caller's cached query, so the first caller's documents were scored against the attacker's query. Version 0.30.0 replaces the client value with a server-generated identifier.

## What was observed

The advisory was published on 23 Sep 2026 and last updated on 5 Oct 2026. Root cause, per the advisory: the header was copied directly into the worker cache key, and the cache lookup did not check that the reader owned the entry (CWE-639, authorization bypass through a user-controlled key). Late-interaction scoring computes a query embedding once and reuses it across the documents scored in the same request; the cache was the hand-off between those steps. A colliding identifier replaced the stored embedding between write and read. The advisory also notes that the shared use counter could be exhausted, producing cache-miss errors, and that the data-parallel router sends requests with the same key to the same engine, which makes the collision deterministic.

```
# Illustrative
# victim:   POST /rerank  X-Request-Id: abc  -> query embedding cached under "abc"
# attacker: POST /rerank  X-Request-Id: abc  -> overwrites cached embedding
# victim's documents are scored against the attacker's query
```

The precondition is flash late interaction, which the advisory states is enabled by default for supported models; non-flash late-interaction scoring was not affected. The effect is an integrity failure in ranking output, not disclosure: in a retrieval pipeline that reranks with a shared vLLM instance, a co-tenant could skew which passages reach the generator. The advisory credits Patch the Planet (a Trail of Bits and OpenAI collaboration), with the finding made using GPT-5.5-Cyber, and lists no workaround.

Rubric rating is medium. The default configuration is affected on a shared server, but the impact is manipulated ranking and errors rather than exposure of another tenant's data, and the advisory's own score is 4.2.

## Mitigation

Upgrade to vLLM 0.30.0 or later; the fix derives the cache key from a server-generated UUID. Until then, avoid sharing a late-interaction scoring server across trust boundaries, or strip and regenerate `X-Request-Id` at a gateway so clients cannot choose it. The broader lesson is that a client-controlled header is not a cache key: any cache that sits between pipeline stages needs server-issued keys bound to the requesting principal.
