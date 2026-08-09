---
caseId: "058"
title: "AWS, Google, and Vercel agent harnesses executed tool calls the model never authorized"
filed: "2026-08-09"
filedDisplay: "09 Aug 2026"
firstObserved: "06 Aug 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Amazon Bedrock AgentCore InvokeHarness API (fixed server-side, no customer action required); underlying open-source strands-agents/harness-sdk (model-skip shortcut unpatched, documentation-only mitigation); Google Agent Development Kit for Python (<2.5.0); Vercel AI SDK harness packages @ai-sdk/harness-codex (<=1.0.28) and @ai-sdk/harness-opencode (<=1.0.27)"
cve: "CVE-2026-18830 (AWS Bedrock AgentCore); CVE-2026-18236 (Google ADK continuation forgery); CVE-2026-64650 / CVE-2026-64651 (Vercel AI SDK harness relays) — collectively demonstrated as the \"CoreBreak\" attack pattern"
readTime: "6 min read"
related: ["014", "038", "055"]
---

## Summary

Researchers presenting at Black Hat USA 2026 disclosed a pattern they call CoreBreak: four separate flaws, one in Amazon Bedrock AgentCore, two in Google's Agent Development Kit for Python, and two in Vercel's AI SDK harness packages, all sharing the same root cause. Each agent runtime's dispatch layer accepted data shaped like a model-generated tool call and executed it without verifying that an actual model turn had produced it. In several of the four paths the model was never invoked at all, so system prompts, content filters, and any other model-level guardrail never had a chance to intervene. AWS, Google, and Vercel each shipped fixes; the open-source Strands SDK that AgentCore's harness is built on retains an unpatched version of the same shortcut, addressed so far only with a documentation warning rather than a code change.

## What was observed

In a normal agent turn, the harness sends the user's request, system prompt, conversation history, and tool definitions to the model, the model returns a structured instruction naming a tool and its arguments, and the harness executes it. The four flaws removed the verification step between that last pair of actions: the runtime checked that incoming data had the shape of a tool call, not that a legitimate model turn had generated it.

```
# illustrative shape of the shortcut (not the literal source)
if message_has_tool_use_block(latest_message):
    stop_reason = "tool_use"
    dispatch(latest_message.tool_use)   # model is never invoked
```

AWS's managed AgentCore InvokeHarness API (CVE-2026-18830, CVSS v4.0 8.6) let an authenticated remote caller place a tool-use content block into the final message of a request; the event loop dispatched the named tool directly. AWS patched the managed service with server-side validation that rejects caller-supplied tool-use blocks before they reach the event loop. The same shortcut exists in the open-source Strands harness-sdk that AgentCore is built on — a helper checks for a tool-use block in the latest message and, if found, skips model invocation entirely. An April pull request warned that externally injected blocks could reach execution this way; it was closed unmerged in June. AWS's position, per the researchers, is that Strands deployments fall under its shared-responsibility model, and the company's response was a new documentation page instructing developers to build message history only from their own application, never from caller-supplied input.

Google's ADK had two distinct gaps, both fixed in version 2.5.0. The first, CVE-2026-18236 (CVSS v4.0 9.3), affected ADK's confirmation mechanism, which lets a developer flag a sensitive tool as requiring human approval before it runs. The confirmation processor never checked that the approved tool matched the tool actually recorded in the session, or that the tool required confirmation in the first place — an attacker able to inject events into session history could forge an approval for an unrelated, unconfirmed tool. The second gap, in ADK's newer resumable-mode flows, accepted user-authored events containing function-call parts and executed them as if the model had issued them; Google's fix now rejects function calls appearing in user-authored messages. Google issued a CVE only for the confirmation-forgery path, since it affects ADK's default configuration; resumable mode is newer and non-default.

Vercel's two flaws sat in the harness relay that lets sandboxed coding agents (Codex and OpenCode) reach host-side tools such as secret lookups and deployment operations. The relay authorized a request if the calling process's command line matched the path of an approved helper script — a check that malicious code already running inside the sandbox (a poisoned dependency or build script, for instance) could satisfy without any model turn occurring. Vercel removed the process-path fallback; the patched relay accepts a request only against an exact, one-time authorization tied to a specific tool name, input, and observed model event.

> This is not prompt injection. There is no probabilistic model to fool and no stronger model that resists it, because the model never gets a turn.

## Mitigation

Upgrade Google ADK for Python to 2.5.0 or later, `@ai-sdk/harness-codex` to 1.0.29 or later, and `@ai-sdk/harness-opencode` to 1.0.28 or later; the AWS managed service required no customer action. Strands harness-sdk deployments outside AgentCore's managed service have no code fix available — treat conversation history, resumable-mode events, and confirmation responses as untrusted input whenever an external caller can shape them, and build message history from application state rather than caller-supplied data. The pattern generalizes beyond these three vendors: any agent harness needs to bind each tool invocation to the exact model event, tool name, arguments, session, and authorization state that produced it, rather than accepting anything shaped like a model-authorized call. A safeguard that lives only in a system prompt or a model's own judgment disappears entirely on any path where the model doesn't run — which is precisely the class of bug this file describes.
