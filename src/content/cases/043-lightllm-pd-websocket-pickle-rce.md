---
caseId: "043"
title: "LightLLM's prefill-decode WebSocket endpoints deserialize network input with pickle, and the server refuses to bind to localhost"
filed: "2026-08-01"
filedDisplay: "01 Aug 2026"
firstObserved: "15 Feb 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "LightLLM (ModelTC/lightllm), PD disaggregation mode WebSocket endpoints /pd_register and /kv_move_status (version 1.1.0 and prior; no fix released as of writing)"
cve: "CVE-2026-26220"
readTime: "5 min read"
related: ["025", "024", "020"]
---

## Summary

LightLLM is a Python inference framework that supports prefill-decode (PD) disaggregation, splitting a request's prompt-processing and token-generation phases across separate GPU nodes for throughput. Worker nodes register with a PD master over WebSocket, and two of the master's endpoints — `/pd_register` and `/kv_move_status` — deserialized incoming binary frames with Python's `pickle.loads()`, with no authentication on either endpoint. A crafted pickle payload sent to either endpoint executed arbitrary commands on the master node. The vulnerability is distinct from a previously reported and still-unfixed ZMQ deserialization issue in the same project; this one was found by independent researcher Valentin Lobstein during a code audit, assigned CVE-2026-26220 (CVSS 9.3) on 12 February 2026, and publicly disclosed on 15 February 2026 after the PD master's GPU-loading requirement made a live proof of concept slower to confirm.

## What was observed

Both endpoints read a binary WebSocket frame and pass it directly to `pickle.loads()`:

```
# lightllm/server/api_http.py — worker registration and
# KV-cache transfer status, both deserialize untrusted input:
data = await websocket.receive_bytes()
obj = pickle.loads(data)  # no auth, no schema, no allowlist
```

`/pd_register` has a two-step protocol — a JSON registration frame followed by binary frames — but the registration step performs no authentication; the `node_id` field accepts any integer, and the `mode` field is checked against a list of valid strings, not verified against any credential. `/kv_move_status` skips even that and accepts a pickle payload on the very first binary frame. Pickle deserialization in Python executes code embedded in the payload's `__reduce__` method during unpickling, before any application-level validation runs; a payload built around `os.system` ran shell commands the moment the frame was read. The startup code for the PD master contains an explicit assertion — `assert manager.args.host not in ["127.0.0.1", "localhost"]` — that prevents the server from binding to loopback. This is deliberate: the whole point of PD mode is that remote worker nodes need to reach the master over the network, so unlike most services where "expose it to the network" is a deployment mistake, here it is the only supported configuration. There is no way to run PD disaggregation mode without the vulnerable endpoints being network-reachable.

> A vulnerability class this old — unsafe deserialization of network-supplied data — doesn't need a novel trigger to stay dangerous. It needs a code path where "network-exposed" and "no authentication" were both true by design, and disaggregated serving keeps creating exactly that path.

The same researcher had reported a related ZMQ `recv_pyobj()` deserialization issue in this project eleven months earlier; it was acknowledged and never fixed. A separate private security report filed through GitHub in November 2025 went unanswered. The identical vulnerability class in the peer project vLLM was assigned CVE-2025-32444 at CVSS 10.0.

## Mitigation

No patched release was available as of the most recent reporting on this issue. Operators running PD disaggregation mode should treat the master node's WebSocket ports as fully untrusted-network-facing regardless of where they sit topologically, and restrict reachability with a network-layer control (firewall rule, service mesh policy, or VPN) rather than relying on the application to authenticate connections, since it does not. Longer term, worker registration and KV-cache status data are simple structured values — node IDs, IP addresses, status enums — with no need for Python's general-purpose object graph; replacing `pickle.loads()` with JSON or a schema-checked format removes the vulnerability class outright rather than papering over this instance of it. Teams evaluating disaggregated-serving frameworks generally should ask, before deployment, which node-to-node channels use pickle or an equivalent unrestricted deserializer, because every one of them is a live RCE candidate the moment a node's network boundary is anything less than fully trusted.
