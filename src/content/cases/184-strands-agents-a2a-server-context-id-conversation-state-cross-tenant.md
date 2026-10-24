---
caseId: "184"
title: "Strands Agents A2A server shared conversation state across callers, exposing other tenants' history and accepting persistent instructions"
filed: "2026-10-24"
filedDisplay: "24 Oct 2026"
firstObserved: "22 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "strands-agents (PyPI, modules containing multiagent.a2a, <1.43.0); @strands-agents/sdk (npm, <1.5.0)"
cve: "CVE-2026-115419 (GHSA-4v6f-7vjh-6x4m, CWE-488, CVSS 3.1 8.1, CVSS 4.0 8.6)"
readTime: "3 min read"
related: ["076", "040", "108"]
---

## Summary

The A2A (agent-to-agent) server component of the Strands Agents SDK did not isolate conversation state between callers. An authenticated remote user could send requests with a different `context_id` and read conversation history belonging to other tenants, and could add persistent instructions that altered model behavior for later callers. Python 1.43.0 and TypeScript 1.5.0 isolate state per `context_id` with an agent factory.

## What was observed

The CVE record was published on 22 Oct 2026 and the GitHub advisory on 23 Oct 2026. Root cause, per the advisory summary: the server held conversation state in a way that, under certain circumstances, was shared across callers presenting different `context_id` values. The advisory text available in this run did not specify those circumstances, the exact state container, or a reporter, and none are asserted here.

Two effects are recorded. First, a caller could read history from sessions it did not own (CWE-488, exposure of data element to wrong session). Second, because the shared state also carried instructions, a caller could add persistent directives that changed the model's behavior for subsequent callers. The second effect is an integrity failure in the agent's context, comparable to stored prompt injection delivered through the transport rather than through retrieved content.

The precondition is an A2A endpoint serving more than one user or tenant from a single agent instance, with a valid low-privilege credential. Deployments that run one A2A server per principal were not exposed. The advisory states that no workaround fully resolves the issue.

Rubric rating is medium rather than the 8.1 headline: the exposed data is conversation history that can be sensitive, but the trigger conditions are unspecified and the multi-tenant single-instance deployment is a deliberate configuration choice, not a default.

## Mitigation

Upgrade `strands-agents` to 1.43.0 or later, and `@strands-agents/sdk` to 1.5.0 or later. Until then, do not expose an A2A server to more than one user or tenant, or run a separate server instance for each. After patching, review A2A logs for unusual `context_id` values and treat histories held by previously shared instances as potentially disclosed; revoke credentials that appeared in them. The broader lesson is that a client-supplied session identifier selects state but does not authorize access to it: the server must bind each identifier to the authenticated principal.
