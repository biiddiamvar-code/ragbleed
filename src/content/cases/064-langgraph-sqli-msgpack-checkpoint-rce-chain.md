---
caseId: "064"
title: "LangGraph's checkpoint SQL injection and its msgpack deserialization bug chained into remote code execution"
filed: "2026-08-13"
filedDisplay: "13 Aug 2026"
firstObserved: "12 Jun 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "langgraph-checkpoint-sqlite (< 3.0.1), langgraph (<= 1.0.9)"
cve: "CVE-2025-67644, CVE-2026-28277 (chained; no combined CVE assigned to the chain itself)"
readTime: "5 min read"
related: ["005", "001", "024"]
---

## Summary

Case 005 covered LangGraph's checkpoint-store SQL injection (CVE-2025-67644) as a disclosure failure: unparameterized filter keys let an attacker read checkpoint contents beyond what a query should return. Researcher Yarden Porat, credited via Check Point Research, showed the same injection could be pushed further. Chained with a separate unsafe msgpack deserialization bug in checkpoint loading (CVE-2026-28277), the SQL injection stops being a read primitive and becomes a way to smuggle a fabricated checkpoint row into the application's own deserializer — turning "attacker can read checkpoint metadata" into "attacker gets code execution on the server." Both component flaws were patched (langgraph-checkpoint-sqlite 3.0.1, langgraph 1.0.10); LangChain's managed LangSmith Deployment platform was not affected, only self-hosted deployments using the SQLite or Redis checkpointer with user-controlled filter input.

## What was observed

LangGraph's checkpointer persists agent state — conversation turns, intermediate reasoning, task progress — so a workflow can resume later. The `get_state_history()` interface retrieves past checkpoints filtered by metadata, and it was this filter path that carried the SQL injection documented in case 005. On its own, that bug let an attacker manipulate the WHERE clause of the underlying query. Porat's contribution was recognizing what an attacker could put in the row it manipulated the query into returning: not just extra legitimate data, but an entirely fabricated row whose checkpoint column held attacker-controlled bytes.

Those bytes mattered because of the second bug. LangGraph checkpoints are serialized with msgpack, and the deserializer supported an `ext_hook` capable of reconstructing arbitrary Python objects — importing a module, resolving an attribute, and invoking it with attacker-supplied data — with no allowlist restricting which modules and attributes were fair game by default. Loading a checkpoint didn't just decode data, it executed a plan for reconstructing it.

```
# 1. malicious filter parameter exploits the SQL injection to make the
#    query return a fabricated row (not one actually written by the app)
# 2. that row's checkpoint column holds an attacker-built msgpack payload
# 3. application deserializes it during normal checkpoint loading
# 4. ext_hook reconstruction executes the attacker's payload
```

Each bug had been assessed individually at moderate severity: LangGraph's own advisory described the deserialization flaw as a "post-exploitation / defense-in-depth issue," reasoning that exploiting it required an attacker to already have privileged write access to the checkpoint store. That assessment held for a standalone deserialization bug, but it assumed away the SQL injection sitting right next to it — a bug that manufactured exactly the "write access to checkpoint store" the deserialization CVE treated as a precondition. Chaining them collapses two moderate findings, each scored under the assumption the other's precondition wasn't freely available, into remote code execution reachable from ordinary application input.

> A vulnerability scored as "requires privileged access" is only as safe as the assumption that privileged access is hard to get. Here, a second bug in the same product handed it out for free.

## Mitigation

Upgrade `langgraph-checkpoint-sqlite` to 3.0.1 or later and `langgraph` to 1.0.10 or later; both fixes are required; patching only one leaves the other half of the chain intact. Independently, set `LANGGRAPH_STRICT_MSGPACK=true` in production, which restricts checkpoint deserialization to a built-in safe set plus a schema-derived allowlist rather than trusting arbitrary `ext_hook` reconstruction — this closes the deserialization side even against injection bugs not yet discovered. Treat any endpoint that filters or queries the checkpoint store on caller-supplied metadata as a SQL injection surface subject to the same parameterization discipline as any other database-backed API. More broadly: severity assessments for a single vulnerability are only valid in isolation. When two moderate bugs sit in adjacent code paths of the same product, whether one bug's stated precondition is satisfiable by the other is exactly the question a standalone CVSS score can't answer.
