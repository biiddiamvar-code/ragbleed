---
caseId: "044"
title: "Semantic Kernel's default vector store built filter expressions with eval()"
filed: "2026-08-03"
filedDisplay: "03 Aug 2026"
firstObserved: "06 Feb 2026"
severity: high
category: "Embedding / vector store exposure"
status: "Patched"
affectedSystems: "Microsoft Semantic Kernel — Python SDK, InMemoryVectorStore filter functionality (<1.39.4); .NET SDK, SessionsPythonPlugin (<1.71.0)"
cve: "CVE-2026-26030 (Python, CVSS 9.9); CVE-2026-25592 (.NET, CVSS 9.9)"
readTime: "5 min read"
related: ["026", "012", "034"]
---

## Summary

Microsoft's Semantic Kernel agent framework shipped two critical remote-code-execution flaws that both trace back to the same design mistake: letting content that flows through retrieval or tool orchestration reach a code-evaluation primitive before anything checks whether it should be trusted. In the Python SDK, `InMemoryVectorStore` — the framework's default, zero-configuration vector store — built its filter expressions as a Python lambda string and ran that string through `eval()`. In the .NET SDK, a separate flaw in `SessionsPythonPlugin` let a model-invoked tool call write files outside the sandboxed Azure Container Apps session used to run generated code. Microsoft disclosed both in a single research post, "When prompts become shells," describing the underlying pattern as indirect prompt injection escalating into host compromise. Patches shipped the same day, in `semantic-kernel` 1.39.4 (Python) and 1.71.0 (.NET).

## What was observed

`InMemoryVectorStore` is the vector store Semantic Kernel reaches for when a developer hasn't wired up Qdrant, Azure AI Search, or another backend — the path most tutorials and quick-start RAG agents take. Its filtering logic accepted a filter expression, interpolated attacker-reachable field values directly into a Python lambda string, and passed that string to `eval()` to produce a callable. Nothing separated data that arrived from a retrieved document, a tool result, or a model's own output from the code being constructed.

```
# filter fields interpolated into a lambda string, then eval()'d
# a value that breaks out of the intended expression runs as code,
# not as a comparison operand
```

Because the filter values could originate from content the agent had merely retrieved — not from a call the developer wrote by hand — a single indexed document containing the right payload was enough to reach `eval()` the next time the agent queried its own store. The .NET flaw followed the same shape from a different angle: `SessionsPythonPlugin` exposed a file-download/upload helper as a kernel function a planner could select on its own, and a `../`-style path in the arguments a model chose to pass let generated code deposit files outside the Container Apps sandbox boundary meant to contain it. Both bugs treat the same trust boundary — retrieved or model-generated content versus code that executes — as though it doesn't exist, once that content is close enough to an interpreter.

> Traditional input sanitization sits outside an agent's runtime; it never sees a payload that only assembles itself inside the framework's own filter-building or tool-dispatch code.

## Mitigation

Upgrade to `semantic-kernel` 1.39.4 or later (Python) and `Microsoft.SemanticKernel.Plugins.Core` 1.71.0 or later (.NET). Treat `InMemoryVectorStore` as unsuitable for any deployment that indexes content from outside the development team, even after patching, since the class exists primarily as a convenience default rather than a hardened production backend. For `SessionsPythonPlugin`, add a function-invocation filter that allow-lists the paths `DownloadFileAsync` and `UploadFileAsync` may touch, rather than trusting whatever the planner supplies. The broader lesson holds beyond Semantic Kernel: once retrieval output can influence a tool call's arguments, and a tool call's arguments can reach a code-evaluation or file-path primitive, the framework has built a prompt-injection-to-RCE pipeline whether or not any single line of code looks dangerous in isolation.
