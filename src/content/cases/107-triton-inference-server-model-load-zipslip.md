---
caseId: "107"
title: "Triton's dynamic model loader extracted a packaged environment archive without checking where its entries pointed"
filed: "2026-09-06"
filedDisplay: "06 Sep 2026"
firstObserved: "18 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "NVIDIA Triton Inference Server for Linux, Python backend EXECUTION_ENV_PATH handling under explicit or poll model-control mode (versions through 26.05; fixed in 26.06)"
cve: "CVE-2026-47627"
readTime: "4 min read"
related: ["021", "026", "090"]
---

## Summary

NVIDIA Triton Inference Server, widely used to serve the embedding and generation models behind RAG pipelines, let a caller register a new model whose Python backend pointed at a packaged conda environment archive. Triton extracted that archive without validating the paths of the entries inside it, so a crafted archive could write files outside the model repository directory entirely — a classic Zip Slip flaw reachable through Triton's model-management API. NVIDIA's own advisory describes the confirmed impact as denial of service; an independently published proof-of-concept demonstrates the underlying primitive is an arbitrary out-of-directory file write, a broader capability than the advisory's DoS-only framing suggests.

## What was observed

Triton exposes a `load_model` call over its HTTP and gRPC management APIs when the server runs with `--model-control-mode=explicit` or `poll` — settings that let operators register or hot-swap models at runtime instead of only loading a fixed set at startup, a common pattern for RAG and agent deployments that need to add or update models without a restart. For a Python-backend model, the registered configuration can include an `EXECUTION_ENV_PATH` parameter pointing at a packaged environment (a tar.gz of a conda environment) that Triton unpacks into a working directory before running the model's code.

```
# illustrative — model config referencing a packaged execution environment
parameters: {
  key: "EXECUTION_ENV_PATH"
  value: { string_value: "$$TRITON_MODEL_DIRECTORY/malicious_env.tar.gz" }
}
```

The extraction routine wrote each archive member to its recorded name under the target directory without confirming the resolved path stayed inside it — the same class of bug this database has already logged in RAGFlow's MinerU integration (case 090). A published proof-of-concept (`AneKazek/cve-2026-47627`) demonstrates the full path end to end against a Triton 26.05 container: it clones a benign sample Python model, adds an `EXECUTION_ENV_PATH` parameter referencing a crafted archive whose one payload entry is named `../../poc_marker`, and calls Triton's `load_model` gRPC endpoint — which carries no authentication of its own — to trigger the extraction. The result is a file written outside `/models`, confirming the traversal reaches the filesystem regardless of what the archive is nominally supposed to contain. The published PoC deliberately writes only a harmless marker file rather than attempting further exploitation, so it demonstrates the write primitive without establishing what NVIDIA's assigned CVSS vector (9.8, with confidentiality and integrity impact both rated high) would require to fully substantiate; NVIDIA's own text confirms only a denial-of-service outcome.

## Mitigation

Upgrade to Triton Inference Server 26.06 or later. Independently of the patch, treat `--model-control-mode=explicit` or `poll` as requiring the same access control as any other administrative interface: Triton's model-management endpoints carry no built-in authentication, so any deployment that exposes ports 8000 (HTTP) or 8001 (gRPC) to a network where not every caller is fully trusted needs an authenticating proxy in front of them, regardless of this patch. Treat `EXECUTION_ENV_PATH` archives from any model registry or pipeline stage that isn't fully trusted as untrusted input requiring extraction inside a sandboxed or chrooted working directory, since the underlying pattern — code that unpacks an archive and trusts the names inside it — tends to reappear in whichever new packaging feature ships next, the same lesson this database has drawn from equivalent bugs in document-parsing pipelines elsewhere in the RAG stack.
