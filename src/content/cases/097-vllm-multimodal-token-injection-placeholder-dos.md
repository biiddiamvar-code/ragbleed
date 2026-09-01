---
caseId: "097"
title: "vLLM's multimodal prompt handling let plain text pose as control tokens and crash workers on missing media"
filed: "2026-09-01"
filedDisplay: "01 Sep 2026"
firstObserved: "12 May 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (>=0.6.1, <0.20.0), multimodal input processing pipeline"
cve: "CVE-2026-44222 (GHSA-hpv8-x276-m59f)"
readTime: "4 min read"
related: ["029", "021", "066"]
---

## Summary

vLLM's multimodal input processor had two related validation gaps in the code path that turns a prompt's text and any attached image or video data into model input. First, text that merely spelled out one of vLLM's internal special-token strings was interpreted as the control token itself rather than as literal user text. Second, a request that declared image or video placeholder sequences without attaching the matching binary media data was processed as if the data were present, and the resulting out-of-bounds array access crashed the worker handling it. Both were unauthenticated and reachable with a plain text-only request, and both were fixed in the same release.

## What was observed

vLLM threads special tokens through its multimodal pipeline to mark where image or video content belongs in a prompt. The processor did not distinguish between that token arriving as an actual control token and the same character sequence arriving as ordinary text a user typed — a request whose text explicitly spelled out the internal token string got it interpreted as a real placeholder, giving an unauthenticated caller a way to inject token-level structure into a prompt using nothing but text.

The second gap sat downstream of the first, in how declared placeholders were matched against actual data:

```
# request declares image/video placeholder sequences (image_grid_thw / video_grid_thw)
# in the prompt text, but attaches no corresponding image or video payload
#
# input-position computation indexes into image_grid_thw / video_grid_thw
# using the declared placeholder count, without checking the arrays hold
# data for that many items -> index into an empty array -> unhandled
# Python IndexError -> worker process exits
```

Because a request declaring placeholders was never checked against whether matching tensors had actually arrived, the position-computation step indexed into arrays sized for data that was never supplied. Python raised an `IndexError` that the request-handling path did not catch, which terminated the worker process rather than returning a validation error to the caller. Any system serving multimodal models through an affected vLLM version was reachable pre-auth by this crash, and — as with other worker-process DoS bugs in this database — the blast radius extends to every other request the same worker was mid-flight on, not just the one that triggered it.

## Mitigation

Upgrade to vLLM 0.20.0 or later, which validates multimodal placeholder counts against actually-supplied data before indexing and treats literal special-token text as ordinary content rather than control input. This site rates the mechanism medium rather than matching any higher headline severity attached to it elsewhere: the confirmed impact is a per-worker crash and a token-level injection primitive, not confirmed data exposure or cross-tenant reach, which keeps it below the cases in this database where an unauthenticated crash takes down an entire shared server rather than one worker (see case 075). The recurring lesson across vLLM's DoS history (see cases 029 and 066) is the same each time: any field in a request that gets used as an array index, a count, or a size needs to be validated against what the request actually contains, not trusted because the request claims it.
