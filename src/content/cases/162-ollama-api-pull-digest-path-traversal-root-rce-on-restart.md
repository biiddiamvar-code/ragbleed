---
caseId: "162"
title: "Ollama's pull endpoint wrote attacker-chosen files outside the model store, yielding root code execution on restart"
filed: "2026-10-11"
filedDisplay: "11 Oct 2026"
firstObserved: "08 Oct 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Ollama (0.34.2 up to, but not including, 0.35.0; earlier versions not confirmed)"
cve: "CVE-2026-103663"
readTime: "3 min read"
related: ["019", "020", "086"]
---

## Summary

Ollama's `/api/pull` endpoint passed layer digests to the `digestToPath` function without validating them. A digest containing traversal sequences resolved to a path outside the model store, allowing an unauthenticated remote client to write a file to an arbitrary location. When the Ollama process could write to `/usr/lib/ollama`, the default in most Ollama Docker images, a planted binary was loaded on the next restart and ran as root.

## What was observed

A model pull downloads layers identified by content digests and stores each under a path derived from its digest. `digestToPath` built that path from the digest string as supplied, so a value with relative-path components escaped the model directory instead of naming a blob inside it. The CVE record classifies the flaw as relative path traversal (CWE-23) combined with improper control of dynamically managed code resources (CWE-913): the write target was a directory from which Ollama loads executable libraries.

```
# pull request references a layer whose digest contains ../ sequences
# digestToPath resolves it to a location under /usr/lib/ollama
# the attacker-served layer content is written there as a binary
# next service restart loads the file -> code execution as root
```

The exploit therefore had two stages: an unauthenticated write through the pull API, then execution deferred to a restart. CERT-PL, which assigned the CVE, scored it CVSS v4.0 9.4 when the server can write to `/usr/lib/ollama` and 6.9 when it cannot. Red Hat scored it 6.2 under CVSS v3.1 with a local attack vector and states its products are not affected. CISA's SSVC entry records no known exploitation and rates the flaw not automatable. RagBleed rates it high because the writable library directory is the default in the common container image and the endpoint requires no credentials.

## Mitigation

Upgrade to Ollama 0.35.0 or later. The CVE record lists no vendor workaround. Compensating controls that follow from the mechanism: run the Ollama process with no write access to `/usr/lib/ollama`, monitor that directory for unexpected files, and keep the API unreachable from untrusted networks, since Ollama ships without authentication. A service that fetches content from remote registries and derives filesystem paths from fields in that content must treat those fields as untrusted input.
