---
caseId: "041"
title: "Flowise's CSV Agent node let prompt injection produce Python that walked past its own sandbox denylist"
filed: "2026-07-31"
filedDisplay: "31 Jul 2026"
firstObserved: "15 Apr 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "Flowise / flowise-components (<= 3.0.13)"
cve: "CVE-2026-41264 (GHSA-3hjv-c53m-58jj)"
readTime: "5 min read"
related: ["007", "002", "034"]
---

## Summary

Flowise's CSV Agent node asks an LLM to translate a user's question about an uploaded CSV into pandas code, then runs that code in a Pyodide (in-process WebAssembly Python) environment on the server. Before execution, the generated code was checked against a list of forbidden regex patterns meant to block imports, `exec`/`eval`, and file or OS access. The denylist was incomplete: an import statement that pulled in `pandas` and `os` together, with `os` aliased to the name `pandas`, matched none of the forbidden patterns and gave the script an `os`-shaped object to call. An attacker able to get the LLM to emit that code — through direct prompt injection into the chat, with no authentication required — could execute arbitrary commands on the Flowise host.

## What was observed

The relevant pattern, `/\bimport\s+(?!pandas|numpy\b)/g`, was written to flag any `import` not immediately followed by `pandas` or `numpy`. It didn't account for comma-separated import lists or aliasing:

```
# denylist checks each import target individually against pandas/numpy,
# but doesn't stop a second, differently-named target riding along:
import pandas as np, os as pandas
pandas.system("id")   # "pandas" now refers to the os module
```

Because the CSV Agent's system prompt is built from the user's question and handed to whatever LLM the chatflow is configured to call, an attacker only needed to phrase a question that induced the model to output this pattern instead of legitimate dataframe code — a direct prompt injection against the agent itself, requiring no login if the chatflow was publicly reachable. A second variant applied to authenticated users who could point a chatflow's model configuration at an attacker-controlled endpoint: that endpoint could return the malicious script directly in place of an LLM completion, skipping the injection step entirely. Either path ended with attacker-chosen code running inside the Pyodide sandbox with access to `os`, and from there to the underlying server process.

## Mitigation

Upgrade to Flowise / flowise-components 3.1.0 or later. The deeper issue generalizes past this one regex: denylisting specific "known-bad" tokens in LLM-generated code is a losing race against the size of the language it's trying to constrain, because the set of ways to reach a dangerous primitive (aliasing, indirection, string construction, encoding) is always larger than the set of patterns written to catch them. Sandboxes that execute model-generated code should constrain by allowlisting a narrow, parseable grammar — arithmetic and named dataframe operations only, checked against an AST rather than a regex — rather than trying to enumerate everything forbidden.
