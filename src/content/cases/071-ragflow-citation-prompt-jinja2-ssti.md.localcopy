---
caseId: "071"
title: "RAGFlow's citation-prompt renderer fed user-controlled text straight into an unsandboxed Jinja2 template"
filed: "2026-08-17"
filedDisplay: "17 Aug 2026"
firstObserved: "09 May 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "RAGFlow, Canvas LLM component citation-prompt rendering (rag/prompts/generator.py, versions <=0.24.0); no patched version listed in the advisory as of writing"
cve: "CVE-2026-45312"
readTime: "5 min read"
related: ["002", "003", "041"]
---

## Summary

RAGFlow's Canvas workflow builder lets any registered user assemble LLM pipelines from a drag-and-drop DSL. One step in that pipeline — the citation-prompt renderer that runs when a workflow cites retrieved chunks — passes user-supplied prompt text straight into an unsandboxed Jinja2 template environment. Because Jinja2's default environment is a general-purpose Python templating engine rather than a content-safe one, a normal low-privilege account can smuggle a template payload into that text and have it evaluated as code on the server, with no API keys, admin role, or pre-existing model credentials required.

## What was observed

The prompt generator at `rag/prompts/generator.py` builds its Jinja2 environment as `jinja2.Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)` — unsandboxed, with no restriction on what a rendered template can reach. Its `citation_prompt()` function renders a user-controlled template string through that environment whenever a workflow has `cite=True` (the default) and retrieval has produced at least one chunk.

The user-controlled string arrives by way of the Canvas DSL: an LLM component's `sys_prompt` field is scanned for `<CITATION_GUIDELINES>` tags, and whatever text sits inside one is handed to `citation_prompt()` as the template itself — not as content to drop into a template, but as the template's own source, meaning it's treated as trusted logic rather than trusted data.

```
# rag/prompts/generator.py, illustrative
PROMPT_JINJA_ENV = jinja2.Environment(autoescape=False, ...)  # unsandboxed

def citation_prompt(user_defined_prompts):
    template = PROMPT_JINJA_ENV.from_string(
        user_defined_prompts.get("citation_guidelines", DEFAULT_TEMPLATE)
    )
    return template.render()  # attacker-controlled Jinja2 syntax executes here
```

Reaching that code path needs no privileged access and no configured model. A self-registered account can add a DuckDuckGo search component ahead of the LLM component purely to populate retrieval chunks — that component needs no API key — and can satisfy RAGFlow's requirement for a "valid" configured model by pointing it at a throwaway HTTP server the attacker controls that mimics an OpenAI-compatible API just well enough to pass validation. Once the workflow runs, the citation renderer evaluates the attacker's Jinja2 payload with the server process's own privileges; the published proof of concept walks Jinja2's `__globals__` chain from inside the template to reach `os.popen`, a well-documented SSTI-to-RCE technique that doesn't depend on any RAGFlow-specific weakness beyond the missing sandbox.

> Any normal user can register, create a Canvas workflow, and trigger the injection — no sandbox service, no embedding model, no pre-existing credentials of any kind.

The published advisory rates this critical (CVSS 9.9), and it holds up under this site's mechanism-based rubric too: self-registration is enabled by default, no special role is required, and the path from "create an account" to "run OS commands on the host" involves no unusual configuration on the operator's part.

## Mitigation

No patched version was listed in the advisory as of this writing. Until one ships, disable self-registration or restrict Canvas workflow creation to trusted accounts, and treat any RAGFlow deployment where ordinary users can build or edit Canvas DSLs as equivalent to giving them a shell on the host. The underlying lesson repeats a pattern already logged in this database for the same product (case 002, RAGFlow's earlier `eval()`-on-sandbox-output flaw): a general-purpose templating or evaluation engine is not a safe place to run text that started out as user input, no matter how many layers of DSL sit between that input and the render call. Jinja2 ships a sandboxed environment built for exactly this situation; reaching for the unsandboxed default on external input is the default-settings failure, not an edge case in configuration.
