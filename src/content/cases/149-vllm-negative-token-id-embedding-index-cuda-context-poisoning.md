---
caseId: "149"
title: "vLLM validated only the upper bound of token IDs on its embeddings and pooling endpoints, so one negative ID poisoned the CUDA context and killed the engine"
filed: "2026-10-05"
filedDisplay: "05 Oct 2026"
firstObserved: "03 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (< 0.28.0), OpenAI-compatible /v1/embeddings and /pooling endpoints serving embedding or pooling models"
cve: "CVE-2026-93592 (GHSA-25q3-v2hm-8vpf)"
readTime: "4 min read"
related: ["029", "097", "121"]
---

## Summary

vLLM's `/v1/embeddings` and `/pooling` endpoints accepted token IDs supplied directly by the client and checked them only against the vocabulary size. A negative ID passed that check and was used as an index into the embedding table on the GPU, where it tripped a device-side assertion. The assertion corrupted the CUDA context, and every later request failed until the process was restarted. The flaw is a single-request, unauthenticated denial of service against embedding backends commonly used to serve RAG retrieval.

## What was observed

The GitHub advisory GHSA-25q3-v2hm-8vpf was published on 03 Sep 2026; CVE-2026-93592 was published on 18 Sep 2026 (CVSS 8.7, CWE-129, improper validation of array index). Affected versions were all releases before 0.28.0.

According to the advisory, the request path accepted pre-tokenized input and enforced an upper bound against the model's vocabulary size. No corresponding lower-bound check existed. A negative integer therefore reached the model runner and was used as an index into the embedding table. The resulting out-of-range access fired a device-side assertion inside PyTorch's indexing kernel. Device-side assertions cannot be caught by Python exception handling; they leave the CUDA context in a failed state, so the engine process did not recover and subsequent requests, including those from unrelated clients, returned errors.

```
# Illustrative, vLLM < 0.28.0 serving an embedding model
POST /v1/embeddings
{"model": "<embedding-model>", "input": [[-1]]}
  -> bound check: id < vocab_size          # passes, no id >= 0 check
  -> embedding_table[-1] on GPU            # device-side assert
  -> CUDA context poisoned; all later requests fail until restart
```

The advisory states that no authentication, special configuration or user interaction was required beyond network access to an exposed embedding or pooling endpoint. Deployments that accept only raw strings from untrusted clients and tokenize server-side were not reachable through this input form, which is the basis of the advisory's workaround.

The rubric rating is medium rather than the CVSS headline: the mechanism exposes no data and is recoverable by restart, but embedding endpoints are a default component of RAG ingestion and query pipelines, so a single request can stall retrieval for every tenant sharing the instance.

## Mitigation

Upgrade vLLM to 0.28.0 or later, which adds a lower-bound check requiring token IDs to be non-negative before any GPU operation. Where an immediate upgrade is not possible, reject negative integers in array inputs at a reverse proxy, accept only string input from untrusted clients, and restrict network access to `/v1/embeddings` and `/pooling` to trusted callers. Run a process supervisor that restarts the engine on failure, and alert on repeated post-restart errors.

Bounds checks on values that index device memory belong at the API boundary; a host-side exception is recoverable, while a GPU-side assertion is not.
