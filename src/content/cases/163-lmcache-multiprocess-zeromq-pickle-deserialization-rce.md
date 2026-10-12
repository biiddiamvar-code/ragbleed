---
caseId: "163"
title: "LMCache multiprocess mode decoded ZeroMQ messages with pickle.loads on an unauthenticated socket"
filed: "2026-10-12"
filedDisplay: "12 Oct 2026"
firstObserved: "07 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "LMCache multiprocess (distributed) mode (0.3.9 through 0.5.5, release candidates up to 0.5.6rc3; no fixed release at disclosure)"
cve: "CVE-2026-105192 (JFrog advisory JFSA-2026-001694382)"
readTime: "3 min read"
related: ["025", "043", "130"]
---

## Summary

LMCache's multiprocess mode, used to share a KV cache across inference processes, opened a ZeroMQ ROUTER socket with no authentication and decoded incoming MessagePack messages with `pickle.loads`. Any client able to reach the socket could execute code as the LMCache process user. JFrog Security Research disclosed the flaw on 7 October 2026 together with a public proof of concept, and no fixed release existed at that time.

## What was observed

The vulnerable path first appeared in version 0.3.9. The server registered a MessagePack extension hook, in `lmcache/v1/multiprocess/custom_types.py`, that handled extension code 1 by calling `DeviceIPCWrapper.Deserialize`. That method passed the attacker-supplied bytes to `pickle.loads`. The ROUTER socket on port 5555 had no CURVE, ZAP, or password protection.

Deserialization ran while the server parsed the arguments of a `REGISTER_KV_CACHE` request, before any request handler executed. A later type error or argument check therefore could not prevent execution; the error was logged only after the payload had run.

```
# DEALER client connects to tcp://<host>:5555 (no credentials)
# sends REGISTER_KV_CACHE with msgpack extension code 1
# payload bytes reach pickle.loads during argument decoding
# code executes as the LMCache user, before handler logic
```

The transport bound to localhost by default. Exposure required a routable address, set through the `--host` option, which multi-node deployments use. LMCache running inside a vLLM process does not open the affected port. JFrog's proof of concept wrote the output of `id` to a file in the container; the official container images run as root, and JFrog did not demonstrate a container escape. The CVSS 3.1 score of 9.8 was assigned by JFrog's CNA for the network-reachable configuration. RagBleed rates the mechanism medium because the default single-host deployment is not reachable, and the exposure depends on an operator choice that cluster deployments commonly make.

## Mitigation

No patched version was available at disclosure; check the LMCache releases for a fix before relying on any version. Until then, keep the default localhost binding, avoid routable `--host` values, and restrict port 5555 to the cluster with firewall rules. Network isolation reduces exposure but does not remove the flaw. JFrog recommends replacing pickle-based network decoding with a safe format and authenticating the transport with CURVE or per-message HMAC. The same pattern appears in other inference-stack components: a cache or scheduler coordination channel treated as internal is an unauthenticated deserialization endpoint once it leaves loopback.
