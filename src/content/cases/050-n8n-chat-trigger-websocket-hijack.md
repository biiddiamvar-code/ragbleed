---
caseId: "050"
title: "n8n's Chat Trigger WebSocket let unauthenticated attackers hijack live human-in-the-loop conversations"
filed: "2026-08-05"
filedDisplay: "05 Aug 2026"
firstObserved: "04 May 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "n8n, Chat Trigger node / Hosted Chat feature (versions before 1.123.32, 2.17.4, 2.18.1)"
cve: "CVE-2026-42228"
readTime: "5 min read"
related: ["009", "038", "016"]
---

## Summary

n8n's Chat Trigger node powers human-in-the-loop (HITL) agentic workflows: an AI agent sends a message, suspends execution, and waits for a human to reply before continuing. The transport for that exchange, a WebSocket served at `/chat`, checked neither the identity of the connecting client nor whether it was entitled to attach to a given conversation. Combined with sequential, guessable execution IDs and a sibling endpoint that revealed which executions were currently waiting for input, this let any unauthenticated network client enumerate live chat sessions, eavesdrop on agent output, and inject messages into someone else's conversation in progress.

## What was observed

The `/chat` route was registered outside n8n's normal authentication pipeline. Routes wired through the framework's decorator system pass through a centralized auth middleware unless explicitly flagged otherwise; `/chat` bypassed that pipeline entirely by being mounted directly with no middleware attached. A client opened the WebSocket by supplying an `executionId`, identifying the suspended workflow run, and a `sessionId`, identifying the conversation inside it. Neither value was bound to an authenticated identity — whoever connected first with a given `sessionId` became that session as far as the server was concerned.

```
# WebSocket handler attached the connection to executionId/sessionId
# directly from client-supplied values, with no ownership check
```

Execution IDs in n8n are sequential integers, so an attacker did not need to know one in advance — they could iterate. A second unauthenticated route, `/form-waiting/:executionId/:suffix`, returned the literal string "waiting" for any execution currently suspended on user input, giving the attacker a live oracle for which IDs were worth attaching to at any given moment. Walking that oracle across the integer space surfaced every active HITL conversation on the instance in real time.

Once attached, the WebSocket was bidirectional. An attacker could read whatever the agent sent back — tool results, retrieved context, summaries intended for the legitimate user — and inject new `sendMessage` frames to steer the conversation, all without ever authenticating to the n8n instance.

> Three separate small gaps — a route outside the auth pipeline, a predictable identifier, and a status oracle for finding live targets — compounded into a complete, unauthenticated hijack of a running conversation.

n8n's own advisory rates this Medium, CVSS 6.3, largely because CVSS scores confidentiality and integrity impact as limited to the chat transcript rather than the underlying system. This rubric rates it higher: exploitation required no privileges of any kind, worked against any publicly reachable Hosted Chat deployment — a default, unremarkable configuration for a customer-facing HITL agent — and gave full read/write control over another user's live session, which can include tool output containing exactly the kind of retrieved or generated data a RAG-backed agent exists to protect.

## Mitigation

Upgrade to n8n 1.123.32, 2.17.4, or 2.18.1 or later, which bind `/chat` connections to an authenticated, authorized session before allowing attachment. Deployments that cannot upgrade immediately should restrict network access to Hosted Chat endpoints and treat any publicly reachable HITL workflow as exposed until patched. More broadly: routes registered outside a framework's declarative auth system are easy to miss in an audit precisely because they don't show up in a grep for the auth decorator — they have to be found by inventorying every `app.use` and `app.all` call directly, the way this vulnerability was.
