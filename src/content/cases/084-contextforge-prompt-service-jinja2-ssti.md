---
caseId: "084"
title: "ContextForge's prompt-template renderer evaluated stored templates in a plain, unsandboxed Jinja2 environment"
filed: "2026-08-26"
filedDisplay: "26 Aug 2026"
firstObserved: "25 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "IBM mcp-context-forge (ContextForge MCP Gateway), mcpgateway.services.prompt_service.PromptService (versions before 1.0.0)"
cve: "No CVE assigned as of writing; tracked as GHSA-vwf3-4xxj-qg6h"
readTime: "4 min read"
related: ["070", "071", "018"]
---

## Summary

ContextForge, IBM's open-source MCP gateway, lets authenticated users register reusable prompt templates that the gateway renders on demand for downstream agents and tools. The rendering code built its Jinja2 environment with the library's plain `Environment()` constructor instead of `SandboxedEnvironment`, so a stored template was evaluated with full access to Python's object model rather than a restricted subset. A user permitted to register or update prompt templates could store a template that ran arbitrary code on the gateway host the next time it rendered. Fixed in mcp-context-forge 1.0.0.

## What was observed

`PromptService._render_template`, in `mcpgateway.services.prompt_service`, takes the text of a stored prompt template and renders it through a Jinja2 `Environment()` — the library's general-purpose templating engine, which by design allows a template to walk Python's attribute chain and reach built-in functions. Jinja2 ships a separate `SandboxedEnvironment` specifically to block that kind of attribute-chain traversal for cases where template text isn't fully trusted; `PromptService` used the unsandboxed one.

```
# mcpgateway/services/prompt_service.py, illustrative
env = jinja2.Environment()            # not SandboxedEnvironment
template = env.from_string(stored_prompt_text)
rendered = template.render(**context)  # attacker's template logic executes here
```

Reaching the flaw required an authenticated account with permission to register or update prompt templates — not ContextForge's full admin role, but not the gateway's default anonymous surface either. That distinction matters for a gateway whose stated purpose is sitting in front of MCP, A2A, and REST/gRPC APIs for multiple downstream integrations: a template-authoring permission that's routine to hand out in a shared deployment becomes, through this bug, a path to code execution with the gateway process's own privileges — potentially reaching whatever credentials the gateway holds for the services it proxies.

## Mitigation

Upgrade to `mcp-context-forge` 1.0.0 or later. The fix does two things: it validates prompt templates before storage (checking brace balance, Jinja2 syntax, and dangerous patterns like `__import__` and dunder attribute access) and applies pattern-based scanning for injection payloads across the resource, prompt, and tool creation and update paths. The narrower lesson for anyone building on Jinja2: `Environment()` and `SandboxedEnvironment` differ by exactly the property that matters when the template text itself is user-controlled, and picking the former is a decision, not a default worth reaching for casually — the same root cause already logged for RAGFlow's citation-prompt renderer in case 071.
