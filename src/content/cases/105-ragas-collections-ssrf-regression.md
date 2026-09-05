---
caseId: "105"
title: "A second RAGAS module repeated the file-fetch bug the first patch didn't reach"
filed: "2026-09-05"
filedDisplay: "05 Sep 2026"
firstObserved: "20 Apr 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "ragas (PyPI package, v0.2.3 through v0.4.3, Collections metrics API)"
cve: "CVE-2026-6587 (GHSA-95ww-475f-pr4f)"
readTime: "4 min read"
related: ["104", "015", "010"]
---

## Summary

RAGAS shipped a fix for an arbitrary file-read flaw in its original multimodal prompt class in early 2025 (case 104). By the time that fix landed, the library had grown a second, independent code path — the newer "Collections" metrics API — that fetched content from `retrieved_contexts` using its own local-file and URL-handling functions. Those functions were never touched by the earlier fix and carried the same unsafe pattern: an attacker-supplied entry in `retrieved_contexts` could make the evaluator issue a request to a target of the attacker's choosing.

## What was observed

The vulnerable functions, `_try_process_local_file` and `_try_process_url` in `src/ragas/metrics/collections/multi_modal_faithfulness/util.py`, exist to let the Collections API's multi-modal faithfulness metric resolve items in `retrieved_contexts` to actual file or network content before scoring. As with the original flaw, the metric that scores retrieval quality is itself a path an attacker can steer, because the content it scores is exactly the content it's told to trust.

The GitLab Advisory Database entry documenting this flaw is explicit about the relationship to case 104: "the security patch for CVE-2025-45691 was applied to a different module only." The Collections API had reimplemented content-fetching logic separately from the `ImageTextPromptValue` path that got hardened, which meant the fix for one instance of the pattern left a second, functionally identical instance untouched. The class of bug — trusting a retrieved-content field to resolve safely to local files or arbitrary network destinations — is Server-Side Request Forgery, CWE-918, the same root cause underlying case 104's arbitrary file read, just reached through a different function that shipped after the first one was already a known problem.

> A patch scoped to the function a researcher reported doesn't patch the pattern that function was an instance of.

As of this writing, the vendor was notified early in the disclosure process and did not respond, no fixed release is available, and proof-of-concept exploit code for the flaw has already been published.

## Mitigation

There is no upstream fix to upgrade to at time of writing. Until one ships, treat any RAGAS evaluation pipeline — Collections API or otherwise — that accepts `retrieved_contexts` from a source you don't fully control as exposed, and add your own network-layer controls in front of it: block outbound requests to loopback, link-local, and cloud-metadata address ranges, and reject `file://` and other non-HTTP schemes before RAGAS ever sees them. The broader lesson repeats the one from case 104: a security fix that targets the specific function named in a CVE, rather than the design pattern that function embodies, leaves every other implementation of that same pattern in the codebase exactly as exploitable as before the patch shipped.
