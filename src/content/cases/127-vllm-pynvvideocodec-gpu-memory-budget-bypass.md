---
caseId: "127"
title: "vLLM let a request pick its own GPU video decoder, and the memory budget never found out"
filed: "2026-09-18"
filedDisplay: "18 Sep 2026"
firstObserved: "16 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (< 0.28.0), Chat Completions and Responses endpoints with PyNvVideoCodec installed"
cve: "CVE-2026-69147 (GHSA-8pw2-6jv3-mj5j)"
readTime: "4 min read"
related: ["117", "121", "123"]
---

## Summary

vLLM deployments that serve video-capable multimodal models reserve GPU memory for decoding up front, based on whatever decoder backend the deployment was started with. A request body could override that choice at call time by setting `media_io_kwargs.video.video_backend` to `pynvvideocodec`, and the server honored it even when the deployment had been configured to decode video in software. Because the memory-reservation logic only ever consulted the startup configuration, the GPU allocations that PyNvVideoCodec's hardware decoder actually made were invisible to the budget meant to protect the KV cache. A caller who could submit video requests could exhaust shared GPU memory and crash worker processes. Fixed in 0.28.0.

## What was observed

vLLM's multimodal input pipeline resolves how to decode an incoming video through a component called `MediaConnector.fetch_video`, which looks up the requested backend in a `VIDEO_LOADER_REGISTRY`. Server operators can install PyNvVideoCodec, NVIDIA's hardware-accelerated decoder, alongside vLLM to speed up video-heavy workloads, and can select it — or a software fallback — at startup. The flaw was that `fetch_video` also accepted a `video_backend` value supplied inside the request itself, and would switch to PyNvVideoCodec on a per-request basis regardless of what the deployment had actually been started with.

```
POST /v1/chat/completions
{
  "messages": [...],
  "media_io_kwargs": {"video": {"video_backend": "pynvvideocodec"}}
}
# server honors this even if startup config selected a software decoder
```

Separately, vLLM's engine pre-reserves a chunk of GPU memory for the KV cache via `_reserve_mm_ipc_gpu_memory`, sizing that reservation from the decoder backend the deployment was configured with at boot. When a request forced PyNvVideoCodec into use anyway, the CUDA context, decoder surfaces, and decoded-frame buffers it allocated were real GPU memory commitments that this reservation logic had never budgeted for and could not later reclaim from. Enough concurrent requests making that same override converted an accounting gap into an out-of-memory condition, taking down inference workers and failing requests server-wide rather than just the requests responsible.

## Mitigation

Upgrade to vLLM 0.28.0 or later, where request-supplied `video_backend` values are constrained to what the deployment allows. Deployments that cannot upgrade immediately and don't need PyNvVideoCodec can avoid exposure by not installing it, since the override has nothing to activate without the package present. More broadly, any inference server that lets a request select among multiple backends for a resource-intensive operation needs its memory or compute budget to be recomputed for whichever backend actually runs — a reservation calculated once at startup and never revisited per request is a budget for a system that no longer matches what's being served.
