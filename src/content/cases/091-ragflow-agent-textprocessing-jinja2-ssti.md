---
caseId: "091"
title: "A second unsandboxed Jinja2 render in RAGFlow's Agent editor let any self-registered user run shell commands"
filed: "2026-08-29"
filedDisplay: "29 Aug 2026"
firstObserved: "01 Apr 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "RAGFlow, Agent workflow \"Text Processing\" (StringTransform) and \"Message\" components (agent/component/string_transform.py, agent/component/message.py; version 0.24.0 and prior)"
cve: "CVE-2026-28797 (GHSA-vvwj-fvwh-4whx)"
readTime: "5 min read"
related: ["071", "090", "002"]
---

## Summary

RAGFlow's Agent editor lets any registered user wire together a workflow from drag-and-drop components, two of which — Text Processing and Message — accept a script or content field that gets rendered through Jinja2 before use. Both components render that field with the plain `jinja2.Template` class rather than Jinja2's sandboxed environment, so a template payload in either field runs with full access to Python's object graph, not just to the variables the component intended to expose. Because RAGFlow ships with self-registration on by default, an attacker needs nothing but an email address to reach this: create an account, drop a Text Processing node into a new agent flow, and the payload runs on the server the moment the flow executes.

## What was observed

Both vulnerable call sites followed the same shape — a user-supplied string checked only for the presence of `{{`, `}}`, or `{%...%}` before being handed to an unsandboxed template class:

```
# agent/component/string_transform.py, illustrative
if self._is_jinjia2(script):                 # true for any string containing {{ }}
    template = Jinja2Template(script)         # unsandboxed jinja2.Template
    script = template.render(kwargs)          # attacker-controlled globals reachable here
```

`agent/component/message.py` repeated the same pattern for its `content` field. Because `jinja2.Template` — as opposed to `jinja2.sandbox.SandboxedEnvironment` — places no restriction on attribute traversal, a payload like `{{ cycler.__init__.__globals__.os.popen('id').read() }}` walks from an innocuous built-in filter object through its `__globals__` back to the `os` module already imported in that scope, then to `popen`. Reported proof of concept confirmed command execution by reading the output back through the Agent's own execution log panel, and from there the accessible template globals reach the server process's environment variables and its `conf/service_conf.yaml` — which holds the MySQL, Redis, MinIO, and Elasticsearch credentials RAGFlow uses internally.

> No API key, no configured model, and no elevated role stand between "click register" and "run OS commands on the host" — only a workflow save and a run button.

In a shared or multi-tenant RAGFlow deployment, that single low-privilege foothold reaches every other tenant's data once the backing datastore credentials are in hand, since those credentials are shared infrastructure rather than scoped per account. This is the same missing-sandbox pattern this database already logged for RAGFlow's citation-prompt renderer (case 071, `rag/prompts/generator.py`) — the researchers who reported this flaw pointed at that exact file as needing the same fix, which means the unsandboxed-Jinja2 footgun has now turned up in at least three separate RAGFlow code paths rather than one.

## Mitigation

The advisory's suggested fix — swap `jinja2.Template` for an instance of `jinja2.sandbox.SandboxedEnvironment`, which blocks attribute access to dunder names like `__globals__` and `__init__` — had not shipped in a tagged release as of this writing, so deployments cannot patch their way out yet. Until it does, disable self-registration (`REGISTER_ENABLED=0`) or restrict Agent-workflow creation to trusted accounts, since either component turns any account able to save a flow into a shell on the host. Given the default-on self-registration, the lack of any privilege requirement beyond a fresh account, and the blast radius in shared deployments, this file rates the flaw high — consistent with the advisory's own critical rating. The recurrence across three separate call sites in the same codebase (cases 002, 071, and this one) argues for an application-wide audit of every `jinja2.Template(...)` and `jinja2.Environment(autoescape=False)` call in RAGFlow, rather than patching each report as it's found; a template engine that can reach `os.popen` from user input is a design defect, not a series of unrelated bugs.
