---
caseId: "021"
title: "vLLM could be handed a malicious video and give up the server"
filed: "2026-02-05"
filedDisplay: "05 Feb 2026"
firstObserved: "02 Feb 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM, multimodal video model support (versions prior to 0.14.1)"
cve: "CVE-2026-22778"
readTime: "4 min read"
related: ["002", "006", "018"]
---

## Summary

vLLM's multimodal input handling accepts a video by URL and parses its container format before passing frames to the model. The parser trusted structural values inside the video file — including a box that describes how frame data is laid out — without validating them against the file's actual size, letting a crafted video drive a memory-corruption bug that led to remote code execution.

## What was observed

Modern video files are organized into nested "boxes" describing metadata and stream layout; one such box (`cdef`, which describes channel/component definitions) contains offset and size fields the parser used to locate frame data. vLLM's parser read those fields and used them to index into the file's data without confirming they stayed inside bounds the file actually had. A crafted `cdef` box with offset and size values engineered to overflow that calculation caused the parser to read or write outside its intended buffer.

```
# simplified: box-declared offset/size used without bounds validation
frame_data = buffer[cdef.offset : cdef.offset + cdef.size]
# attacker-controlled cdef values can exceed buffer bounds
```

Because this path is reachable simply by submitting a video URL to a normal, documented API call — the same way any legitimate multimodal request would supply one — no authentication and no unusual configuration were needed beyond having video-model support enabled, which is precisely the feature organizations turn on when they want it. The resulting memory corruption gave an unauthenticated attacker code execution on the inference server itself: not just the model's outputs, but the process serving it, including whatever prompts, credentials, or infrastructure access that process had.

For a RAG or multimodal retrieval pipeline specifically, inference servers frequently sit close to retrieval infrastructure and internal services by design, since that's the point of serving models at scale. A remote code execution bug in the serving layer isn't contained to "bad model output" — it's a foothold inside whatever network segment the inference server occupies.

## Mitigation

Upgrade to vLLM 0.14.1 or later, which adds bounds validation to the affected video-parsing path. If upgrading isn't immediately possible, disable multimodal video support until patched — the vulnerability isn't reachable without it enabled. More broadly, treat any file-format parser handling attacker-influenced input (video, image, or document formats accepted from users or retrieved content) as a meaningful attack surface in its own right, independent of the model behind it; structural fields inside a file are exactly as untrusted as any other user-supplied value; and should be validated against real, on-disk bounds rather than followed on the file's own say-so.
