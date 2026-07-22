---
caseId: "023"
title: "A two-year-old Redis RCE sat undetected until an AI tool found it"
filed: "2026-06-08"
filedDisplay: "08 Jun 2026"
firstObserved: "05 May 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Redis (versions 7.2.0 through 8.6.2)"
cve: "CVE-2026-23479"
readTime: "5 min read"
related: ["002", "021", "022"]
---

## Summary

Redis is commonly deployed as a cache and, increasingly, as a vector-search layer for RAG workloads — which puts it directly in the retrieval path for systems that treat it as trusted infrastructure. A use-after-free bug in how Redis handles blocked clients, sitting in the codebase since 2023, let an authenticated attacker corrupt memory badly enough to execute arbitrary code on the server. It was found not by a person reviewing the code, but by an autonomous AI security tool.

## What was observed

Redis supports blocking commands — a client can ask to wait until data becomes available rather than polling. The logic that "unblocks" a waiting client didn't handle one particular error path correctly: if a blocked client got evicted partway through being unblocked, the server could end up using a pointer to that client's memory after it had already been freed. That's a use-after-free, one of the more dangerous classes of memory bug, because the freed memory can be reallocated for something else by the time the stale pointer gets used.

The demonstrated exploit chain built on that primitive in stages: a Lua script leaked a heap pointer, further manipulation triggered the use-after-free itself, and the attacker then overwrote a function pointer to redirect execution — ultimately reaching arbitrary code execution on the host running Redis. Exploitation requires prior authentication, which meaningfully narrows who can reach it — but Redis deployments with weak, shared, or overly broad credentials are common enough in practice that this requirement provides less protection than it appears to on paper.

```
# unblockClientOnKey() — src/blocked.c
# client pointer used after being freed when eviction interrupts unblock
```

The bug had existed in stable Redis releases for roughly two years before this disclosure — introduced by two ordinary-looking commits in early 2023 that nobody flagged during review. It was part of a batch of five separate RCE-class Redis vulnerabilities disclosed around the same time, including a related flaw specifically in Redis's VectorSets feature — the vector-similarity search functionality Redis added for exactly the kind of embedding lookups RAG pipelines rely on.

## Mitigation

Upgrade to the patched release for your branch: 7.2.14, 7.4.9, 8.2.6, 8.4.3, or 8.6.3. Because exploitation depends on having valid credentials rather than on any particular configuration mistake, audit your Redis ACLs specifically: remove unnecessary permission categories (CONFIG, scripting, and broad key access are the ones worth scrutinizing first), disable Lua scripting where it isn't actually needed, and treat "authenticated" as a much lower bar than "trusted" when Redis sits anywhere near retrieval infrastructure that handles real user data.
