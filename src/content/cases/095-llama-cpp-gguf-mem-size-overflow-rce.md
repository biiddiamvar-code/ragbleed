---
caseId: "095"
title: "llama.cpp checked every tensor-size addition for overflow but not their sum, and a fixed bug reopened"
filed: "2026-08-31"
filedDisplay: "31 Aug 2026"
firstObserved: "12 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "llama.cpp (builds <= b8145; fixed in b8146) — gguf_init_from_file_impl() in gguf.cpp, reached via llama-quantize, llama-imatrix, llama-gguf, and any GGUF load path using no_alloc=false"
cve: "CVE-2026-27940"
readTime: "6 min read"
related: ["072", "020", "048"]
---

## Summary

A prior llama.cpp vulnerability, CVE-2025-53630, was fixed by adding an overflow check to the loop that accumulates GGUF tensor sizes into a running total. The check worked for each individual addition, but a second calculation a few lines further down — the total memory to allocate for the parsed model's in-memory context — added that running total to an unrelated tensor-overhead figure with no equivalent check. A GGUF file with two oversized tensors could pass the fixed check at every individual step while still making the unchecked final sum wrap around to a small number, silently reopening the class of bug the earlier patch was meant to close.

## What was observed

The per-addition guard capped `ctx->size` correctly: each tensor's padded size was checked against `SIZE_MAX - ctx->size` before being added, so no single addition could overflow undetected. A researcher found that two enormous I8 tensors could each individually satisfy that check while their sum landed just below `SIZE_MAX`, and the next line reused that huge value in a fresh, unguarded computation:

```
# mem_size = (n_tensors + 1) * tensor_overhead + ctx->size   <- no overflow check here
# ctx->size near SIZE_MAX makes this addition wrap to a few hundred bytes
```

`ggml_init()` allocated a buffer sized to that wrapped, undersized value, and the subsequent `fread()` — which still believed it needed to read the original, enormous `ctx->size` worth of tensor data — wrote hundreds of bytes past the end of that buffer. By tuning the tensor dimensions so the wrapped allocation landed inside glibc's tcache range, the researcher found that the corrupted heap chunk's `free()` skipped the integrity check that would otherwise have aborted the process, letting execution continue with attacker-controlled data sitting in a reusable memory pool. From there, planting a fake function pointer in the GGUF file's data section and getting it dereferenced was enough to hijack control flow; the published proof of concept resolved `system()` at runtime, embedded its address in the crafted file, and obtained a root shell via `system("/bin/sh")` on both x86_64 and ARM64 Linux hosts. The bug lives specifically in the `no_alloc=false` code path, so `llama-server`'s ordinary model-loading route is unaffected — the exposure is in the auxiliary tools that parse GGUF files directly, chiefly `llama-quantize` and `llama-imatrix`, both of which are routine steps when preparing a downloaded model for local serving.

## Mitigation

Upgrade to llama.cpp build b8146 or later, which adds the missing overflow check to the `mem_size` calculation. Because the exposure runs through tools that process GGUF files a user has downloaded rather than through network-facing inference, the practical mitigation is the same one that applies to any binary file format parsed before a trust decision is made: treat GGUF files from public model repositories as untrusted input, verify them against a known hash or signature before running `llama-quantize` or `llama-imatrix` against them, and don't run those tools as a privileged user. This is the second time an overflow in this exact function has been reported and patched; a fix that validates each step of a calculation but not the calculation's own output is a pattern worth checking for elsewhere in the same parser.
