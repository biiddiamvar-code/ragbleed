---
caseId: "039"
title: "Qdrant's diagnostic logger endpoint let a low-privilege caller overwrite its own config file"
filed: "2026-07-30"
filedDisplay: "30 Jul 2026"
firstObserved: "05 Feb 2026"
severity: high
category: "Embedding / vector store exposure"
status: "Patched"
affectedSystems: "Qdrant (>=1.9.3, <1.15.6)"
cve: "CVE-2026-25628 (GHSA-f632-vm87-2m2f)"
readTime: "5 min read"
related: ["026", "019", "013"]
---

## Summary

Qdrant's `POST /logger` endpoint, meant for runtime diagnostic tuning, accepted a caller-controlled file path for its on-disk log destination and enforced no authorization check on the request — only authentication, which any API-key holder including read-only ones satisfies. Combined with a second endpoint that can be made to write attacker-chosen content into that log stream, a caller with minimal privileges could redirect logging into Qdrant's own configuration directory, inject a valid YAML config override, and have it take effect on the next restart. In containerized deployments with a writable config directory, the same technique escalates to arbitrary file read and remote code execution.

## What was observed

The `/logger` endpoint lets a caller enable on-disk logging and specify the log file path via an `on_disk.log_file` field, with no restriction on where that path points. Qdrant's `PATCH /collections/{name}` endpoint, separately, echoes the (invalid) collection name back into an error message that gets written to the log — and that name is taken directly from the URL, unsanitized. Sending a collection name containing URL-encoded newlines and YAML syntax causes the log entry for that request to contain attacker-chosen YAML, not just an attacker-chosen string.

Chained together: point the log file at `config/local.yaml` inside Qdrant's configuration directory, then send a crafted `PATCH /collections/...` request whose "collection name" is actually a YAML fragment setting `service.static_content_dir` to `..`. The resulting log file is valid YAML once the surrounding log-format text is ignored, and Qdrant treats `config/local.yaml` as a higher-priority override on top of its main config. After a restart — triggered by normal operations, an out-of-memory kill, or a crash — the poisoned `static_content_dir` value comes into effect, and any file readable by the Qdrant process becomes reachable through its own web UI path, including `/etc/passwd` and the main config file (which can itself contain a master API key). A further variant of the same primitive targets `/etc/ld.so.preload` instead of the Qdrant config, which the researcher demonstrated escalating to full remote code execution by having a subsequently-loaded shared object execute on the next process action that consults `ld.so.preload`.

```
# minimal privilege required: any authenticated API key, including read-only,
# can reach /logger — the endpoint checks authentication but not authorization
POST /logger  {"on_disk": {"enabled": true, "log_file": "config/local.yaml", ...}}
PATCH /collections/<url-encoded-YAML-payload>   # injects the override via the access log
```

> Qdrant Cloud is not affected — its configuration directory isn't writable by the running process. The vulnerability requires the specific, common condition of a self-hosted deployment where Qdrant can write to its own config path, which describes most default Docker deployments.

## Mitigation

Upgrade to Qdrant 1.15.6 or later. Where upgrading isn't immediate, restrict `/logger` to management-privileged credentials only — or disable the endpoint entirely if runtime log-level tuning isn't needed — and, independently, ensure Qdrant's configuration directory is not writable by the Qdrant process in production, mirroring how Qdrant Cloud is unaffected by design. The underlying lesson generalizes beyond this one endpoint: any handler that writes caller-influenced content to a file the application later re-reads as trusted input — a log file promoted to config, a cache file promoted to code — needs both strict authorization and strict output encoding, because the danger isn't the write itself, it's what the file becomes the next time the process starts.
