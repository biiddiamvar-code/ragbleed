---
caseId: "072"
title: "A race condition in llama.cpp's idle-unload feature let unauthenticated requests turn freed memory into remote code execution"
filed: "2026-08-18"
filedDisplay: "18 Aug 2026"
firstObserved: "07 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "llama.cpp, llama-server --sleep-idle-seconds model-unload feature (builds b7492 through b9060); llama.cpp underlies Ollama, LM Studio, Jan, GPT4All, and a large share of local-inference tooling"
cve: "CVE-2026-43631"
readTime: "5 min read"
related: ["020", "048", "043"]
---

## Summary

Cyera Research's months-long audit of llama.cpp — the C/C++ inference engine that underlies Ollama, LM Studio, Jan, GPT4All, and most local-model tooling — surfaced ten memory-safety vulnerabilities, two of them critical (CVSS 9.2). The most severe, CVE-2026-43631, is a use-after-free in llama-server's optional `--sleep-idle-seconds` feature: a cost-saving option that unloads a model from memory after a period of inactivity and reloads it on the next request. A request that lands during that unload window can end up dereferencing a freed vocabulary pointer, and an attacker who times and sizes requests carefully can reclaim that freed memory with attacker-controlled data — reaching remote code execution over an unauthenticated network connection. As of publication, five of the ten findings, including both critical ones, remained unpatched upstream.

## What was observed

The `--sleep-idle-seconds` flag lets operators reclaim GPU memory between requests, a pattern the researchers describe as common in centralized deployments where a single local model sits behind an internal API that multiple internal applications call — exactly the setup organizations reach for when redirecting existing "talk to a cloud AI service" code at an internal model instead. When the idle timer elapses, llama-server frees vocabulary-related structures as part of the unload; if a new request arrives while a concurrent worker thread still holds a reference to that structure, the thread can end up dereferencing the now-freed pointer.

Because llama-server's allocator behavior can be influenced by request size, the freed region can be reclaimed with attacker-chosen content before the dangling pointer is dereferenced — the standard use-after-free-to-code-execution primitive. Reaching the code path requires no authentication: llama-server's OpenAI-compatible completion endpoints carry no built-in access control, so any client able to reach the listening port can attempt exploitation, timing requests around the sleep-transition window.

```
# illustrative sequence, not exploit code
1. server idles past --sleep-idle-seconds threshold
2. unload begins: vocab structure freed
3. attacker request arrives mid-unload, worker thread still holds old pointer
4. attacker's next request is sized to reclaim the freed memory
5. worker thread dereferences the freed pointer -> attacker-controlled data executes
```

Cyera's researchers noted the same vulnerability class runs through the reference code that many mobile and offline local-inference apps copied from llama.cpp, and that a comparable chain could be driven to arbitrary code execution "with the app's own permissions and access to its private data" on mobile targets — meaning the blast radius extends well past server deployments.

> Two of the ten findings carry a CVSS of 9.2; as of this writing, both remain unpatched in the upstream project.

The researchers say they went through llama.cpp's normal disclosure channel first; several reports were closed without a fix and the formal CVE-assignment process stalled for months, after which they worked with an independent disclosure organization to get the findings catalogued and published unofficial patches themselves for the issues the maintainers had not addressed. llama.cpp's own security policy notes the project is maintained by volunteers on a "reasonable-effort basis" and asks reporters for at least 90 days before public disclosure — a constraint this incident suggests the rest of the local-inference ecosystem, now standing on that single volunteer-maintained engine, cannot always wait out on its own schedule.

## Mitigation

No official patch exists for CVE-2026-43631 as of publication. Operators running llama-server with `--sleep-idle-seconds` enabled should disable the flag until a fix ships, or restrict network access to the inference port to trusted callers only — llama.cpp's own security guidance already advises against exposing llama-server directly to an untrusted network. Because Ollama, LM Studio, Jan, GPT4All, and numerous smaller projects vendor or wrap llama.cpp internally, downstream maintainers and self-hosters should track llama.cpp's own security advisories directly rather than assume a wrapping project will re-publish them promptly: the volunteer-maintained core of the local-inference stack is a single point of failure for a very large number of downstream products, most of which their users do not realize are the same engine underneath.
