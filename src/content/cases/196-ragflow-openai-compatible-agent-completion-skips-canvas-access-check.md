---
caseId: "196"
title: "RAGFlow's OpenAI-compatible agent completion branch returned before the canvas access check, letting any authenticated user run another user's private agent by UUID"
filed: "2026-11-06"
filedDisplay: "06 Nov 2026"
firstObserved: "05 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "infiniflow RAGFlow (>=0.25.2, <0.27.3; fixed in 0.27.3)"
cve: "CVE-2026-119337 (GHSA-c6q8-23rp-32cv, CWE-862, CVSS 3.1 7.1)"
readTime: "3 min read"
related: ["176", "164", "166"]
---

## Summary

The `POST /api/v1/agents/chat/completions` endpoint in RAGFlow handled requests carrying the OpenAI-compatible flag in a branch that returned before the agent access check ran. Any authenticated user who knew the UUID of another user's private agent could execute it and read its output. The fix shipped in RAGFlow 0.27.3.

## What was observed

The endpoint contains two paths. The regular sessionless path calls `UserCanvasService.accessible(...)` and rejects callers who do not own or share the agent. The OpenAI-compatible path calls `completion_openai` and returns earlier in the function, so the check was never reached. The advisory also records that `get_agent_dsl_with_release` loaded a canvas by its raw agent ID and ignored the `tenant_id` argument, so ownership was not verified downstream either.

```
# user2, valid session, agent UUID owned by user1 ("Only me")
# POST /api/v1/agents/chat/completions            -> code 103, permission denied
# same request with "openai-compatible": true      -> HTTP 200, user1's workflow output
```

The reporter reproduced this on a local v0.27.2 instance with two ordinary accounts. The unauthorized run also appeared in the owner's Management log page. "Only me" is the default visibility for agents, so the affected configuration was the default one. The advisory states that workflows with tools or data sources could leak retrieved data or trigger side effects; the reporter did not test this.

The advisory lists CVSS 3.1 7.1 (High). RagBleed rates the mechanism medium: the attacker needs a valid account and the victim's agent UUID, which is not enumerable by guessing, and demonstrated impact was limited to workflow output. The rating would move to high where agent UUIDs are exposed in shared links, logs or exports, or where agents hold retrieval over sensitive knowledge bases.

The advisory's published fields list no patched version and state the flaw was present on main at commit `15b6668dd8f7`. The v0.27.3 release notes, dated 23 Oct 2026, list "Fix authorization for OpenAI-compatible agent completions" (PR #19817). The two records were written at different times, and the release notes are taken as the later and authoritative statement.

## Mitigation

Upgrade RAGFlow to 0.27.3 or later. Until then, restrict registration and API key issuance to trusted users, treat agent UUIDs as secrets, and review agent run logs for executions by accounts other than the owner. Where an API offers more than one response format, the format switch must change serialization only. Authorization belongs in a single shared step that precedes every branch.
