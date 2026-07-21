---
caseId: "020"
title: "Ollama's model loader leaked its entire process memory to anyone who asked"
filed: "2026-05-07"
filedDisplay: "07 May 2026"
firstObserved: "02 Feb 2026"
severity: high
category: "Disclosure failure"
status: "Patched"
affectedSystems: "Ollama (versions before 0.17.1)"
cve: "CVE-2026-7482 (\"Bleeding Llama\")"
readTime: "5 min read"
related: ["006", "015", "013"]
---

## Summary

Ollama's GGUF model loader reads a tensor's offset and size directly from the model file to know how much data to copy. It never checked whether that declared size actually fit inside the file. A crafted GGUF file with an inflated size value made the loader read past the end of its allocated buffer and into whatever else happened to be sitting in the process's memory — including other users' prompts, API keys, and environment variables — then hand that memory back as if it were model data.

## What was observed

Quantizing or converting a model in Ollama involves reading tensors described by an offset and a size, then copying that many bytes starting at that offset. The functions responsible for this trusted the file's own claims about size without checking them against how much data the file actually contained. Handing Ollama a GGUF file where the declared size exceeded reality caused the read to run past the buffer's real boundary and pull in adjacent heap memory instead of stopping.

That heap memory isn't empty. In a running Ollama process, it can hold other requests' prompts, system prompt content, and process environment variables — which commonly includes API keys and other secrets set at deployment time. Because the vulnerable path is reachable through Ollama's own model-creation API, and the resulting "model" file — heap contents included — could then be pushed out through a separate, unauthenticated push endpoint, an attacker needed nothing more than network access to the server to pull sensitive memory out and exfiltrate it to infrastructure they controlled.

```
# fs/ggml/gguf.go — tensor offset/size trusted without bounds checking
// declared_size > actual_remaining_file_length → read past buffer
```

Ollama ships with no authentication by design, on the assumption that it's meant to run locally. In practice, the documented `OLLAMA_HOST=0.0.0.0` configuration — used specifically to let other machines on a network reach it — is common enough that researchers estimated roughly 300,000 internet-exposed instances at time of disclosure. A tool built for a single-user local machine and a tool reachable across a corporate network or the open internet need very different trust assumptions, and this vulnerability sat exactly at that mismatch.

The disclosure process is its own lesson here. The vulnerability was reported in early February 2026 and patched by February 25 — but the release wasn't flagged as a security fix, no CVE existed yet, and the researcher's requests to MITRE went unanswered for months. Without a CVE, scanners and patch-management tooling had nothing to flag, which meant a patched-but-unlabeled fix left operators with no signal to prioritize updating for nearly three months.

## Mitigation

Upgrade to Ollama 0.17.1 or later, which validates tensor size and offset against the actual file length before reading. If you run Ollama reachable beyond localhost — intentionally or via `OLLAMA_HOST=0.0.0.0` — put authentication and network restrictions in front of it regardless of this specific patch; the tool's own default assumption is that nothing else is necessary, and that assumption doesn't hold once the server is reachable by anyone other than the machine's own user. This case is also a reminder to track patch notes for undisclosed fixes, not just CVE feeds — a fix can exist and be silently unflagged for months.
