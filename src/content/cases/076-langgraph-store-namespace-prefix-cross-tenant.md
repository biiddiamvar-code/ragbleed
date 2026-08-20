---
caseId: "076"
title: "LangGraph's Postgres and SQLite stores matched memory namespaces across tenant boundaries"
filed: "2026-08-20"
filedDisplay: "20 Aug 2026"
firstObserved: "06 Aug 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "langgraph-checkpoint-postgres and langgraph-checkpoint-sqlite (all versions before 3.1.1)"
cve: "CVE-2026-71433 (GHSA-47pj-3jcm-6whg)"
readTime: "4 min read"
related: ["005", "064", "038"]
---

## Summary

LangGraph's Store API is the mechanism agents use for cross-thread, long-term memory — the layer that lets a workflow write "what it knows" once and retrieve it in later conversations, typically scoped to a user, customer, or tenant via a hierarchical namespace. The Postgres and SQLite store backends persisted those namespaces as a single dot-joined string and scoped every read with a SQL `LIKE` prefix match. `LIKE` has no concept of the namespace's own separator, so a read scoped to one tenant's namespace also matched any sibling namespace whose flattened string happened to share the same leading characters. No crafted input was required — an ordinary, correctly-scoped request was enough to pull back another tenant's stored memories.

## What was observed

LangGraph represents a namespace as a tuple, for example `("memories", "alice")`. The Postgres and SQLite stores flatten this to `memories.alice` for storage, and a scoped `search()` or `list_namespaces()` call built its query as `WHERE namespace LIKE 'memories.alice%'`. That pattern matches `memories.alice` exactly, but it also matches `memories.alice2`, `memories.alice-internal-notes`, and anything else beginning with the same characters — the dot in the stored string carries no special meaning to `LIKE`, so the segment boundary a hierarchical namespace is supposed to enforce simply isn't there at the storage layer.

```
# illustrative: scoped memory read, pre-fix
namespace = ("memories", "alice")
flattened = ".".join(namespace)              # "memories.alice"
query = f"SELECT * FROM store WHERE namespace LIKE '{flattened}%'"
# also returns rows under "memories.alice2", "memories.alice-team", etc.
```

Applications built on LangGraph commonly use the namespace precisely as a tenant or user boundary — a customer-support agent keying memory to a customer ID, a multi-user assistant keying it to an account ID, a SaaS product keying it to a workspace slug. In any of these, a user's own, entirely legitimate memory lookup could silently return another tenant's stored data whenever that tenant's identifier happened to prefix-match. Tenant and account identifiers in production are frequently sequential, slug-based, or otherwise predictable, which makes "sharing a prefix" far more common in practice than the bug's abstract description suggests.

> The application asked for its own memory. The store handed back its neighbor's too.

## Mitigation

Fixed in `langgraph-checkpoint-postgres` and `langgraph-checkpoint-sqlite` 3.1.1, which anchor namespace matching on segment boundaries rather than raw string prefixes. Any application persisting LangGraph store state to Postgres or SQLite should upgrade both packages immediately and audit whether memory ever crossed tenant lines while the affected versions were in production — the vendor's own advisory notes no evidence of in-the-wild exploitation, but the bug required no special access beyond an ordinary scoped read, so logs are unlikely to distinguish an exploit attempt from normal use. This site rates the mechanism high against the advisory's own medium (CVSS 5.3): the CVSS score discounts the bug for requiring some attacker-controlled namespace to line up with a victim's, but namespace values in real deployments are exactly the kind of predictable identifiers — user IDs, account slugs, incrementing tenant numbers — that make that alignment trivial rather than exceptional. The broader lesson holds beyond this one library: a hierarchical boundary that exists only in application-level string formatting, and gets enforced with a general-purpose pattern match at the storage layer, is not a tenant boundary at all.
