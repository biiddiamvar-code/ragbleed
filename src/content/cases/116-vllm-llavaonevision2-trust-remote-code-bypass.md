---
caseId: "116"
title: "vLLM's trust_remote_code=False did not stop a malicious processor class from running"
filed: "2026-09-13"
filedDisplay: "13 Sep 2026"
firstObserved: "12 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM, LlavaOnevision2 processor loader (versions prior to 0.28.0)"
cve: "CVE-2026-90553"
readTime: "4 min read"
related: ["021", "048", "006"]
---

## Summary

vLLM's model-loading path for LlavaOnevision2 fetched a processor class named in a model's configuration and executed it, without checking whether the caller had set `trust_remote_code=False`. A model repository pointing at an attacker-controlled `processing_llava_onevision2.py` ran that file's code with the authority of the vLLM process, regardless of the safety flag operators rely on to block exactly this.

## What was observed

vLLM, like most Hugging Face-compatible serving stacks, offers `trust_remote_code` as the boundary between "load only the model's weights and vetted code" and "also execute arbitrary Python the model repository supplies." Operators who set it to `False` are relying on that flag to stop a compromised or malicious model definition from running code on their infrastructure. The LlavaOnevision2 processor loader in vLLM did not consult that flag: when a model configuration named `processing_llava_onevision2.py` as its processor class, the loader fetched and executed the file whether or not remote code execution had been explicitly disabled.

```
# affected loader (simplified):
processor_cls = fetch_remote_module(config.processor_class)
# no check against trust_remote_code before executing processor_cls
```

The attack surface is the model-loading step itself, which makes this a supply-chain problem as much as a code-execution one. Any workflow that lets a model name, path, or repository be influenced by someone outside the operator's own trust boundary — a shared model registry, a user-selectable model parameter, a RAG pipeline that loads embedding or reranking models by configuration — inherits this. `trust_remote_code=False` is the specific control operators add to make exactly that kind of workflow safe; a loader that silently ignores it for one model family leaves the door open while the sign on it reads closed.

## Mitigation

Upgrade to vLLM 0.28.0 or later, which enforces `trust_remote_code` in the LlavaOnevision2 loader. Until patched, treat any deployment that serves LlavaOnevision2 models from configuration sources outside your own control as exposed regardless of how `trust_remote_code` is set, and restrict model loading to a pinned, reviewed set of repositories rather than caller- or config-supplied names. More generally: a safety flag is only as good as its enforcement at every code path that needs it — a security control that covers most model-loading routes but not all of them gives operators false confidence that a documented mitigation is actually in effect.
