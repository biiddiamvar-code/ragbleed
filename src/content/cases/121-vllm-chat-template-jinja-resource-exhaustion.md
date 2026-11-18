---
caseId: "121"
title: "An unbounded Jinja render in vLLM's chat_template argument could wedge every chat endpoint"
filed: "2026-09-15"
filedDisplay: "15 Sep 2026"
firstObserved: "14 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Disclosed, patch guidance pending"
affectedSystems: "vLLM (0.27.0, 0.27.1), OpenAI-compatible /v1/chat/completions endpoint"
cve: "CVE-2026-90878"
readTime: "4 min read"
related: ["029", "097", "117"]
---

## Summary

vLLM's OpenAI-compatible server renders a Jinja chat template on every request to `/v1/chat/completions` to turn a message list into the token sequence the model actually sees. The template itself, or the `chat_template` argument a caller can supply alongside a request, is evaluated as real Jinja — which supports loops, ranges, and string operations, not just variable substitution. A crafted template using a large or deeply nested `range()` could make that single rendering step consume CPU and memory disproportionate to the size of the request that triggered it, tying up the worker handling it and, per the vLLM maintainers' own fix description, risking a state where the whole chat-completions surface stops responding to anyone else.

## What was observed

The vulnerability is a resource-consumption flaw (CWE-400) in the Jinja Template Rendering component of the chat-completions request path. vLLM lets a request override the model's default chat template by passing one directly, and prior hardening had already closed off some paths that accepted an unvalidated template — but the surface remained wide enough that a request carrying a template with a large or nested `range()` construct could still reach the renderer with no bound on how long evaluation was allowed to run or how many instructions it could execute.

```
# illustrative: a request-supplied template that costs little to send, a lot to render
{% for i in range(100000) %}
  {% for j in range(100000) %}
    {{ i * j }}
  {% endfor %}
{% endfor %}
```

Because Jinja is a general-purpose templating language embedded directly in the request-handling path, the cost of evaluating a template scales with what the template asks for, not with the size of the HTTP request that carried it — a few hundred bytes of template source can demand billions of loop iterations. vLLM's own advisory for the fix describes the worst case as an authenticated API client being able to "permanently wedge all chat-style endpoints via CPU or memory exhaustion," which matters because many self-hosted vLLM deployments put the OpenAI-compatible API directly behind minimal or no additional authentication, making "authenticated" a low bar in practice.

## Mitigation

At the time of writing, a fix had been proposed upstream — static AST validation to reject dangerous template patterns (excessive `range()`, string multiplication, deeply nested loops) before rendering, an async render timeout, and, in vLLM's Rust frontend, a bounded instruction-fuel budget per render — but had not yet been merged into a release. Until a patched version ships, operators should disable or tightly restrict any caller's ability to supply a custom `chat_template` at request time, and should not treat "authenticated" as a sufficient control if authentication on the deployment is itself minimal. Rated medium in line with the CVSS assessments so far: exploitation requires reaching the completions endpoint at all, and the consequence is availability loss rather than data exposure — but a single crafted request degrading service for every other caller of a shared inference endpoint is a familiar failure mode for anything that evaluates a general-purpose template language inline with request handling, and it is the kind of bug that tends to resurface in a new code path each time a template feature is extended.
