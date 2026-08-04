---
caseId: "048"
title: "vLLM gated malicious model loading with a single assert statement, and Python's optimizer deletes those"
filed: "2026-08-04"
filedDisplay: "04 Aug 2026"
firstObserved: "02 Apr 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (versions <0.22.0), cross-encoder pooling models (SequencePooler, TokenPooler)"
cve: "CVE-2026-41523"
readTime: "4 min read"
related: ["021", "029", "026"]
---

## Summary

vLLM restricted which PyTorch activation functions a HuggingFace model's `config.json` could request by wrapping the check in a Python `assert` statement — the sole enforcement mechanism on that path. Python strips `assert` statements at compile time when the interpreter runs in optimized mode (`python -O` or `PYTHONOPTIMIZE=1`), a flag documented for production use. With the check compiled away, an attacker-controlled string from a malicious model's configuration reached an unrestricted import-and-call function, giving arbitrary code execution on the inference server the moment a victim loaded that model.

## What was observed

vLLM's cross-encoder pooling code reads an activation-function name out of a model's `config.json` — either `sentence_transformers["activation_fn"]` or `sbert_ce_default_activation_function` — and resolves it to a live Python object to call. The only thing standing between that attacker-supplied string and execution was a single assertion:

```
# vllm/model_executor/layers/pooler/activations.py
assert function_name.startswith("torch.nn.modules."), (
    "Loading of activation functions is restricted to "
    "torch.nn.modules for security reasons"
)
fn = resolve_obj_by_qualname(function_name)()
```

`resolve_obj_by_qualname()` is an unrestricted import gadget: it splits the string on the last dot, imports the module portion, and returns the named attribute. When Python runs under `-O`, every `assert` in the process is a no-op — the interpreter discards them at compile time, regardless of what condition they check. A model published with a crafted `config.json` and a cross-encoder architecture (BERT- or RoBERTa-style sequence classification) could therefore point `function_name` at any importable callable, and vLLM would import and invoke it during model initialization, with the privileges of the vLLM process.

The advisory places this in the same vulnerability class as CVE-2017-1000433, a pysaml2 authentication bypass caused the same way, and notes that both Bandit and Ruff flag assert-based security checks by default (rule B101 / S101) — precisely because they vanish under optimization. Django removed its own remaining assert-based security checks for the identical reason. `resolve_obj_by_qualname` is called from roughly twenty other locations in vLLM's codebase with no validation of its own; this was the one place an external, attacker-controlled string reached it directly.

Exploitation required three things to align: the victim running vLLM under `-O` or with `PYTHONOPTIMIZE=1` set, the victim choosing to load a model from an untrusted or unvetted source, and that model using a cross-encoder architecture. None of those is the default vLLM configuration, which is why this rates medium here despite the GitHub Advisory's CVSS score of 7.5 (High): the impact once triggered is full code execution on the inference server, but reaching it needs an opt-in performance flag stacked on top of a user willingly pulling an unvetted model — a materially narrower path than an unauthenticated, default-configuration RCE.

## Mitigation

Upgrade to vLLM 0.22.0 or later, which replaces the assertion with an explicit conditional raise that survives optimized mode. Independent of version, treat `python -O` / `PYTHONOPTIMIZE=1` as incompatible with any security-relevant assertion anywhere in a dependency chain you don't fully control — the flag doesn't just remove debug noise, it silently deletes every enforcement point written as `assert`. And apply the same rule to model provenance that applies to any other untrusted artifact: a HuggingFace model's `config.json` is attacker-controlled input the instant the model comes from outside your own organization, and code that resolves fields out of it into live imports needs an allowlist that can't be compiled away.
