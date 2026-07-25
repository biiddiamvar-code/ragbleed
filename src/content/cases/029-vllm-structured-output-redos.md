---
caseId: "029"
title: "A single crafted regex could hang a vLLM inference worker indefinitely"
filed: "2026-07-25"
filedDisplay: "25 Jul 2026"
firstObserved: "06 Jul 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM, structured_outputs.regex API parameter (xgrammar and outlines backends, versions <0.24.0)"
cve: "CVE-2026-55574"
readTime: "4 min read"
related: ["021", "025", "020"]
---

## Summary

vLLM's structured-output feature lets a caller constrain a model's generation to match a regular expression, compiling that pattern into a grammar the decoder enforces token by token. The API parameter carrying that regex, `structured_outputs.regex`, passed the caller-supplied string straight to the grammar compiler with no timeout and, in one of vLLM's two compilation backends, no complexity check at all. A single request containing a regex built from nested quantifiers could drive the compiler into exponential state-space expansion, hanging the worker that handled it indefinitely.

## What was observed

vLLM supports two backends for compiling a regex into an executable grammar: xgrammar and outlines. In xgrammar, the caller-supplied pattern reached the underlying regex compiler with no guard on complexity and no compilation timeout — it started compiling and ran until it finished or the process was killed. Outlines fared a little better: its validation step rejected patterns using constructs like lookarounds or backreferences, but that check screened for specific disallowed syntax, not for complexity. A pattern built entirely from allowed constructs — quantifiers nested inside quantifiers — passed validation cleanly and still triggered catastrophic, exponential blow-up in the compiler's internal state space.

```
# structurally "valid" under outlines' construct check —
# nested quantifiers still trigger exponential state expansion
pattern = "(a+)+" * N   # illustrative, not the literal payload
```

Because `structured_outputs.regex` is a documented, ordinary part of vLLM's API — used for JSON mode, tool calling, and any workflow that constrains model output to a schema — no special access or unusual configuration was needed to reach the vulnerable code path. One request with an adversarial pattern hung the worker that processed it.

This is a case where we rate below the CVSS headline (7.5–8.7, HIGH) rather than above it, as cases here sometimes do. The mechanism is real and trivially triggered, but its blast radius is bounded: it costs one worker per malicious request, the worker recovers on restart, and no data — model output, prompts, credentials, or otherwise — is exposed at any point. That's a genuine availability bug against a common feature, not a path to compromise, which is why it lands as medium under our rubric even though an unauthenticated, single-request, default-configuration DoS would ordinarily push toward the top of that range.

## Mitigation

Upgrade to vLLM 0.24.0 or later, which adds a compilation timeout and complexity screening to both backends. Where upgrading isn't immediate, avoid exposing `structured_outputs.regex` to untrusted callers, or front it with a proxy that enforces its own regex-complexity limits and request timeouts independent of vLLM's internal handling. The general failure isn't specific to regex: any feature that compiles or executes a caller-supplied grammar, pattern, or expression needs a resource budget enforced at the boundary, because "syntactically valid input" and "computationally cheap input" are not the same property, and validating only the first leaves the second wide open.
