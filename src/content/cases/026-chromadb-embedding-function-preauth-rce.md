---
caseId: "026"
title: "ChromaDB loaded a model before it checked who was asking"
filed: "2026-07-24"
filedDisplay: "24 Jul 2026"
firstObserved: "13 May 2026"
severity: high
category: "Embedding / vector store exposure"
status: "Disclosed, patch guidance pending"
affectedSystems: "ChromaDB, Python FastAPI server (all versions >=1.0.0; Rust server unaffected)"
cve: "CVE-2026-45829 (\"ChromaToast\")"
readTime: "5 min read"
related: ["012", "013", "019"]
---

## Summary

Chroma's Python server handler for creating a collection loaded the caller's embedding-function configuration — including, for certain embedding functions, arbitrary keyword arguments — before it ran its own authentication check. An attacker who set `trust_remote_code: true` and pointed the configuration at a HuggingFace repository they controlled got Python code execution inside the server process, without ever presenting credentials. As of this writing there is no patch.

## What was observed

Chroma ships two server implementations: a Rust frontend, unaffected, and a Python FastAPI server still used by many self-hosted and development deployments. The vulnerable code path sits in the handler for `POST .../collections`. That handler parses the request body and calls a function that instantiates the named embedding function from the supplied configuration — before it calls the function that checks the caller's authorization.

For embedding functions backed by the `transformers` library, instantiation means calling `SentenceTransformer(model_name_or_path=..., **kwargs)`. The server's validation on those kwargs checks only that each value is a primitive type (string, bool, int, and so on) — a check `trust_remote_code: true` passes without difficulty, since `True` is a primitive. That flag reaches `transformers.AutoModel.from_pretrained()`, which — when told to trust remote code — dynamically imports and executes the Python module shipped alongside the named model. Point `model_name` at a HuggingFace repo containing a malicious `auto_map` entry, and the import executes attacker code as a side effect of "loading a model."

> The request that triggers this can still return a 403 afterward. The auth check does eventually run — it's just downstream of the point where the damage is already done.

A second variant makes this worse in multi-tenant deployments: an authenticated attacker can poison a collection's stored embedding-function configuration once, and any later client — including a legitimate one — that causes the collection to re-embed executes the same payload. The ordering bug isn't just a pre-auth hole; it also means the SDK trusts server-stored configuration it shouldn't.

A process compromised this way typically has read access to the entire vector store across all tenants and collections, plus whatever embedding-provider and object-storage credentials are mounted for the server — the same credentials the RAG pipeline needs to do its job.

## Mitigation

No fixed version exists for the Python FastAPI server at time of writing; the researchers who reported it (HiddenLayer) describe over ten months of follow-up without a maintainer response. If you can, switch to Chroma's Rust server — it doesn't go through the vulnerable code path. If you must run the Python server, put authentication in front of it at a reverse proxy or service mesh layer, since Chroma's own token check runs too late in the request lifecycle to help; specifically gate the collection-creation endpoints there. Block egress from the Chroma host to huggingface.co if your deployment doesn't need it, and watch `~/.cache/huggingface/modules/transformers_modules/` for directories your own ingestion jobs didn't create. The general lesson: when a handler does anything that instantiates code, fetches a remote resource, or has side effects, authorization has to run first — not "eventually," and not after the expensive part of the request has already executed.
