---
caseId: "025"
title: "sglang's inference transport deserializes network input with pickle — and still does"
filed: "2026-03-20"
filedDisplay: "20 Mar 2026"
firstObserved: "12 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "sglang, ZMQ transport layer for disaggregated serving (all versions as of writing)"
cve: "CVE-2026-3059 / CVE-2026-3060"
readTime: "5 min read"
related: ["021", "024", "002"]
---

## Summary

sglang's disaggregated-serving mode splits inference across separate prefill and decode processes that talk to each other over ZMQ sockets. Those sockets bind to every network interface and deserialize whatever arrives on them using Python's `pickle.loads()` — no authentication, no validation, and unlike an equivalent flaw already fixed in a peer framework, no patch yet at time of writing.

## What was observed

Disaggregated serving is a performance pattern: separating the compute-heavy prefill step from the token-by-token decode step lets each run on hardware suited to it, coordinating over a fast transport. sglang implements that coordination with ZMQ PULL sockets, which listen for incoming messages and hand them to `pickle.loads()` directly. A ZMQ PULL socket bound to all interfaces, deserializing pickle data from the network with no authentication step in front of it, means anyone who can reach the port can supply the bytes that socket deserializes — and pickle deserialization of untrusted bytes is equivalent to remote code execution.

```
# ZMQ PULL socket, all interfaces, no auth
socket.bind("tcp://0.0.0.0:<port>")
data = socket.recv()
obj = pickle.loads(data)  # attacker-controlled bytes, executed on load
```

This is the same vulnerability class that earned vLLM a perfect CVSS 10.0 score for an equivalent flaw in its own ZeroMQ transport, and that showed up again in LightLLM's WebSocket-based prefill-decode transport (where a nonce meant to gate deserialization defaulted to an empty string — falsy in Python, so the check silently never ran). sglang has a separate, already-CVE'd flaw in its HTTP `/update_weights_from_tensor` endpoint, but the ZMQ transport's exposure is distinct and, as of this writing, unpatched: multiple independent researchers reported it over the course of a year, and CERT/CC assigned CVE numbers in March 2026 after apparently getting no more response from maintainers than the original reporters did.

That last detail is worth filing on its own. A CVE existing doesn't mean a fix exists — CERT/CC assigning identifiers is a coordination mechanism, not a patch. Scanners and dependency-tracking tools that treat "has a CVE" as equivalent to "someone is handling it" will miss that this one, specifically, has neither an official statement from the maintainers nor a shipped fix.

## Mitigation

No patch is available at time of writing. If you operate sglang in disaggregated-serving mode, do not expose the ZMQ transport ports beyond a network you fully trust and control — treat this the same as you would an admin interface with no login, because functionally that's what it is. If your deployment doesn't need disaggregated serving, disable it. Track sglang's repository directly for a fix rather than relying on vulnerability feeds alone, since the gap between "CVE assigned" and "fix shipped" is exactly the gap this case sits in.
