---
caseId: "118"
title: "LangGraph.js's Redis checkpointer let one filter value pull every tenant's conversation history"
filed: "2026-09-14"
filedDisplay: "14 Sep 2026"
firstObserved: "17 Feb 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "@langchain/langgraph-checkpoint-redis (npm, < 1.0.2)"
cve: "CVE-2026-27022 (GHSA-5mx2-w598-339m)"
readTime: "4 min read"
related: ["005", "064", "076"]
---

## Summary

`@langchain/langgraph-checkpoint-redis`, the Redis-backed checkpoint store for LangGraph's JavaScript SDK, builds RediSearch queries by interpolating caller-supplied filter keys and values directly into query syntax. RediSearch treats several characters as operators rather than literal text, and the package never escaped them. A filter value containing RediSearch's OR operator could rewrite the query's logic well enough to bypass the `thread_id` constraint entirely, returning checkpoint data — stored conversation history — from every thread in the store rather than the one the caller was scoped to.

## What was observed

LangGraph's `RedisSaver` and `ShallowRedisSaver` classes expose a `list()` method (surfaced to application code via `getStateHistory()`) that filters checkpoints by fields such as `thread_id` and `source`. Internally, both classes built the RediSearch query string by dropping filter values straight into tag-query syntax, with no escaping of RediSearch's special characters — among them `|`, which RediSearch parses as OR with looser precedence than the implicit AND joining adjacent clauses. A query the application intended as `(@thread_id:{alice}) (@source:{loop})` — read as "thread alice AND source loop" — became something else entirely once an attacker supplied a filter value like `x}) | (@thread_id:{*`:

```
# intended query, thread-scoped:
(@thread_id:{alice}) (@source:{loop})

# attacker sets filter.source = "x}) | (@thread_id:{*"
# resulting query:
(@thread_id:{alice}) (@source:{x}) | (@thread_id:{*})
# RediSearch precedence reads this as:
# (thread_id:alice AND source:x) OR (thread_id:*)
# the OR clause matches every thread in the store, unconditionally
```

Any application that let end users influence filter values — a chat UI exposing search or history filters over an HTTP endpoint, for instance — handed that same injection point to anyone who could reach it. No elevated privileges were needed beyond whatever access let a user call the history endpoint in the first place; the thread-isolation boundary that separated one tenant's conversation history from another's existed only in the unescaped assumption that filter values wouldn't contain RediSearch syntax.

## Mitigation

Upgrade to `@langchain/langgraph-checkpoint-redis` 1.0.2 or later, which adds an `escapeRediSearchTagValue()` step that backslash-escapes RediSearch's special characters in both filter keys and values before they reach the query builder. The fix is backward compatible — existing filter values that don't rely on RediSearch syntax continue to work unchanged. As defense in depth beyond the patch, applications that expose filtering to end users should validate filter keys against an explicit allowlist rather than passing client-supplied objects through unmodified; a query language that reserves characters for structure will keep producing this class of bug in any component that treats caller input as pre-formed query syntax instead of as data to be escaped first.
