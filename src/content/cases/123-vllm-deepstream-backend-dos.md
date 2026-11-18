---
caseId: "123"
title: "vLLM's DeepStream backend skipped pixel-limit checks on the video decode path"
filed: "2026-09-16"
filedDisplay: "16 Sep 2026"
firstObserved: "25 Aug 2026"
severity: low
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (<0.27.0) with the DeepStream GPU video-decode backend enabled, OpenAI-compatible multimodal endpoints"
cve: "CVE-2026-78684"
readTime: "3 min read"
related: ["021", "097", "117"]
---

## Summary

vLLM's multimodal request path decodes video inputs through one of several GPU-backed decode backends, applying pixel-limit checks meant to cap how large a single frame or clip is allowed to be before decoding starts. Prior to 0.27.0, vLLM failed to classify DeepStream — NVIDIA's video-processing backend — as a GPU backend subject to that enforcement. An unauthenticated caller could select DeepStream at request time and submit a video that bypassed the resource controls entirely, initializing a process-wide GPU decode pool sized to the attacker's input rather than any configured limit, and degrading service for every other concurrent request against the same server.

## What was observed

The flaw (CWE-400, uncontrolled resource consumption) was a gap in backend classification rather than a missing check outright: vLLM's pixel-limit enforcement existed and worked correctly for backends the code recognized as GPU-based, but DeepStream fell outside that classification. Because the decode pool DeepStream initializes is process-wide rather than per-request, a single crafted request was enough to affect the whole server's concurrent request handling, not just the caller's own session — consistent with the "partial denial of service for concurrent requests" impact described in vLLM's own advisory. The fix, landed in commit `e23b19309b8705b21c3b3ff4129c9974ba15a419` and released in 0.27.0, corrected the backend classification so DeepStream requests pass through the same pixel-limit path as every other GPU decode backend.

> A resource limit that only some backends inherit is, in practice, a resource limit that doesn't exist for the backend that was missed.

## Mitigation

Operators running vLLM before 0.27.0 with DeepStream enabled for video decoding should upgrade. The public CVSS score (5.3, medium) reflects an unauthenticated, network-reachable trigger, but this case is rated low here: DeepStream is an opt-in GPU backend rather than vLLM's default video path, so exploitation depends on a deployment choice most self-hosted instances won't have made, and the documented consequence is partial resource exhaustion for concurrent requests rather than a full outage or any data exposure. The pattern is worth tracking regardless of this instance's severity — vLLM has shipped several separate resource-limit gaps across different multimodal decode paths (see related cases below), which suggests per-backend enforcement, added incrementally as backends are added, is an easy place for a new one to be missed.
