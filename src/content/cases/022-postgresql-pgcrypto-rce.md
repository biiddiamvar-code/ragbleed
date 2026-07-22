---
caseId: "022"
title: "A 20-year-old encoding bug in PostgreSQL's pgcrypto gave attackers a path to RCE"
filed: "2026-02-15"
filedDisplay: "15 Feb 2026"
firstObserved: "11 Dec 2025"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "PostgreSQL core, pgcrypto extension (versions prior to 18.2, 17.8, 16.12, 15.16, 14.21)"
cve: "CVE-2026-2005 / CVE-2026-2006"
readTime: "5 min read"
related: ["012", "019", "002"]
---

## Summary

pgvector runs as an extension inside an ordinary PostgreSQL server — which means any vulnerability in PostgreSQL itself is a vulnerability in every RAG stack storing embeddings there, whether or not the RAG pipeline ever touches the affected code path directly. Researchers found exactly that kind of bug in pgcrypto, a commonly enabled encryption extension: a heap buffer overflow in ciphertext decoding that had gone unnoticed in PostgreSQL's codebase for roughly two decades.

## What was observed

pgcrypto's decryption routines parse length fields embedded in the ciphertext they're given to figure out how much data to write. Those length fields were trusted without being checked against the size of the buffer actually allocated to hold the result. Ciphertext crafted with an inflated length value drove a heap write past the end of that buffer — a classic, if long-lived, memory-corruption bug: attacker-controlled input dictating how far past a boundary the program writes.

An authenticated attacker able to supply ciphertext to a pgcrypto decryption function could turn that overflow into arbitrary code execution as the operating system account running the database process — not just corrupted data, but a shell on the database host, with database contents and potentially anything else reachable from that host along with it.

The age of the bug is the part worth sitting with. This wasn't a flaw introduced by a rushed feature or a recent refactor — it sat in a widely used, heavily audited open-source database for around twenty years before a dedicated research effort (ZeroDay.Cloud 2025, in collaboration with Wiz Research) surfaced it. Popularity and age are not evidence of safety; they're evidence that a bug is well hidden.

## Mitigation

Upgrade to PostgreSQL 18.2, 17.8, 16.12, 15.16, or 14.21 — whichever matches your major version — as soon as possible; PostgreSQL's own guidance treats staying on an older minor release as higher risk than upgrading. If you're running pgvector for embedding storage, this patch applies to you even if your application never explicitly calls pgcrypto: it's the same database process. In the meantime, ensure PostgreSQL isn't directly internet-exposed, restrict connectivity to known application subnets, and rotate broadly shared database credentials — reducing blast radius while you schedule the update, not as a substitute for it.
