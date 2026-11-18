---
caseId: "130"
title: "vLLM's disaggregated-serving KV connectors let a client's transfer parameters crash the decode engine three separate ways"
filed: "2026-09-23"
filedDisplay: "23 Sep 2026"
firstObserved: "21 Sep 2026"
severity: low
category: "Denial of service / resource exhaustion"
status: "Disclosed, patch guidance pending"
affectedSystems: "vLLM (<= 0.29.0), NIXL, P2P/ZeroMQ tiering, and Mooncake KV-transfer connectors in disaggregated prefill/decode deployments"
cve: "CVE-2026-94622, CVE-2026-94624, CVE-2026-94625, CVE-2026-94626 (KV-transfer connector DoS batch)"
readTime: "5 min read"
related: ["127", "121", "123"]
---

## Summary

vLLM's disaggregated prefill/decode mode splits inference across separate worker processes that hand off KV cache state through a pluggable connector — NIXL, a ZeroMQ-based peer-to-peer tier, or Mooncake. All three connectors read `kv_transfer_params` out of the client's own request body to decide how to run that handoff, and none of the three validated what came back. Four CVEs disclosed the same day cover three independent ways an unprivileged caller could turn that trust into a server-wide outage: an uncaught exception from a malformed parameter, an unbounded socket allocation from a fabricated peer address, and a resource leak from requests the server had already rejected. Not yet fixed in a tagged release as of this writing; a fix commit exists upstream.

## What was observed

Disaggregated serving exists so a deployment can run prefill and decode on separate worker pools and move KV cache between them instead of recomputing it. The connector abstraction that does the moving takes its instructions from `kv_transfer_params`, a dictionary the calling client supplies alongside the completion request — the same trust boundary vLLM has hit before with request-supplied backend selectors (case 127).

The NIXL connector's metadata handling (CVE-2026-94622) assumed that dictionary would always contain the keys it needed. A request with an incomplete `kv_transfer_params` entry reached `EngineCore` scheduling and raised an uncaught `KeyError`, killing the decode engine outright. A second NIXL flaw (CVE-2026-94626) went the other direction: the connector never checked the `tp_size` value a request supplied, so an attacker could hand it an arbitrary size and force an allocation sized to match, exhausting memory until the kernel OOM-killed the decode worker.

The P2P tier, used when `OffloadingConnector` is configured with a peer-to-peer secondary tier, took `kv_transfer_params` host and port values at face value and opened a ZeroMQ socket to whatever address it was given (CVE-2026-94624):

```
# attacker-supplied kv_transfer_params
{"remote_host": "10.0.0.99", "remote_port": 1}
# connector opens a ZMQ session to that address and holds the socket
# until the peer-session quota is exhausted, then raises an uncaught ZMQError
```

Because the address doesn't need to answer, an attacker could open sessions faster than they'd ever time out, and the quota-exhaustion path itself crashed `EngineCore` rather than degrading gracefully. Separately, the Mooncake connector (CVE-2026-94625) left a different gap: when it rejected a prefill request, the transfer placeholder it had already created for that request was never cleaned up. Enough rejected requests exhausted the sender task pool while health checks kept reporting success, delaying legitimate requests by up to eight minutes with no visible failure signal.

All four share a root cause: connector code trusted request-supplied fields describing a low-level, cross-process resource handoff — sizes, addresses, dictionary shape — without validating any of it against the deployment's actual topology.

## Mitigation

No tagged vLLM release contains the fix at time of writing; the upstream commit is available for deployments that build from source. Until a release ships, operators running disaggregated prefill/decode with NIXL, P2P tiering, or Mooncake should treat the KV-transfer endpoints as internal-only and keep them off any network path reachable by untrusted clients — none of these connectors were designed to validate a hostile caller's transfer parameters, and disaggregated serving is not a default or common vLLM configuration, so exposure is limited to operators who have deliberately built this topology and exposed it to the same clients as the completion API. The broader pattern is the same one behind case 127: a request body is an input to be validated like any other, even when the field in question exists to configure infrastructure rather than describe a prompt.
