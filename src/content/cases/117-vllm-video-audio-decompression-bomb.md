---
caseId: "117"
title: "vLLM's audio decode-size limit didn't follow audio extracted from video"
filed: "2026-09-13"
filedDisplay: "13 Sep 2026"
firstObserved: "12 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM, NanoNemotronVL models with use_audio_in_video enabled (versions >=0.10.2, <0.28.0)"
cve: "CVE-2026-90554"
readTime: "3 min read"
related: ["021", "029", "097"]
---

## Summary

vLLM enforces a decode-size and duration limit on audio submitted directly through its speech input path, guarding against decompression-bomb inputs that expand to enormous size in memory. That guard was never wired into the separate code path that extracts audio from video input for NanoNemotronVL models, so a small, highly compressed video could still force gigabytes of decode-time memory allocation and take down the serving worker.

## What was observed

vLLM's `AudioMediaIO` path already applied `VLLM_MAX_AUDIO_DECODE_DURATION_S` and `VLLM_MAX_AUDIO_DECODE_BYTES` when a caller uploaded audio directly — a limit added specifically to stop decompression-bomb-style inputs from exhausting server memory during decode. NanoNemotronVL models support a separate feature, `use_audio_in_video`, that pulls the audio track out of a submitted video before feeding it to the model. That extraction path, implemented in `_extract_audio_from_videos`, called the same underlying decoder (`load_audio_pyav`) but did not pass either limit through:

```
# direct audio upload path: limits enforced
load_audio_pyav(audio_bytes, max_duration_s=..., max_decode_bytes=...)

# video-extracted audio path: limits omitted
load_audio_pyav(BytesIO(video_bytes))
```

The result was a second entry point into the same decoder that the original fix never reached. An attacker who supplied a small, highly compressed video as multimodal input — with `use_audio_in_video=True` configured, a normal setting for this model family rather than an unusual one — could trigger audio decoding that expanded to gigabytes in memory, exhausting the worker and denying service to other requests. No authentication beyond ordinary API access was required.

## Mitigation

Upgrade to vLLM 0.28.0 or later, which applies the decode-size and duration limits to the video-extracted audio path as well. This is a variant of a familiar failure mode: a resource guard added at one call site into a shared function doesn't protect a second call site into the same function unless someone checks every caller, not just the one that prompted the original fix. Teams patching a resource-exhaustion or decompression-bomb bug should grep for every caller of the affected decoder or parser, not just the one named in the advisory, before considering the fix complete.
