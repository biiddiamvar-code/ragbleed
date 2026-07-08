---
caseId: "005"
title: "LangGraph's checkpoint store was queryable through its own filter keys"
filed: "2026-03-31"
filedDisplay: "31 Mar 2026"
firstObserved: "27 Mar 2026"
severity: medium
category: "Disclosure failure"
status: "Patched"
affectedSystems: "LangGraph, SQLite checkpoint implementation"
cve: "CVE-2025-67644"
readTime: "5 min read"
related: ["004", "001", "003"]
---

## Summary

LangGraph persists the state of agent workflows — conversation turns, intermediate reasoning, task progress — in a checkpoint store, queried by metadata filter keys. Those keys were passed into SQL queries without proper parameterization, letting an attacker manipulate the query itself rather than just the value being searched for.

## What was observed

Checkpointing is what lets a LangGraph agent resume a long-running or multi-turn workflow: every step's state gets written down, keyed by metadata, so it can be looked up later. The SQLite-backed checkpoint implementation built its lookup queries by inserting the metadata filter keys into the SQL statement without the same parameterization discipline applied to the corresponding values. Because those keys could be influenced by whatever was writing checkpoint metadata — which, in an agentic pipeline, can include data derived from retrieved documents or model output — an attacker with that kind of influence could shape the underlying SQL query rather than just supply a search term.

```
# filter keys inserted into the query unparameterized
query = f"SELECT * FROM checkpoints WHERE {filter_key} = ?"
# filter_key can originate from retrieved or model-derived data
```

The practical impact is exposure of the checkpoint store's contents beyond what the querying code intended to retrieve — meaning conversation history, task state, and any other session data written to checkpoints could be read outside the workflow's own scope. It doesn't hand over the host the way a sandbox escape does, but a conversation history containing user data or business context is itself the asset most RAG deployments are trying to protect.

## Mitigation

Update to the patched LangGraph release, which parameterizes filter keys the same way it already parameterized values. Where checkpoint metadata is derived even indirectly from untrusted input (retrieved documents, model output, user-supplied fields), treat it as you would any other user input reaching a database query — never as internal, trusted data.
