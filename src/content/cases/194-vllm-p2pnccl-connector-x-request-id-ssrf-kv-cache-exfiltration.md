---
caseId: "194"
title: "vLLM P2pNcclConnector parsed a peer address out of the caller-supplied X-Request-Id header, directing prefill workers to send KV-cache tensors to an arbitrary host"
filed: "2026-11-05"
filedDisplay: "05 Nov 2026"
firstObserved: "09 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (>=0.9.2, <0.24.0), only with kv_connector=P2pNcclConnector and kv_role=kv_producer"
cve: "CVE-2026-116176 (GHSA-vfp2-c8pq-v6h6; CWE-918; the upstream advisory lists no CVE, the NVD record was published 25 Oct 2026 with CVSS v4 8.8)"
readTime: "4 min read"
related: ["182", "168", "163"]
---

## Summary

In vLLM deployments using the P2P NCCL KV connector for disaggregated prefill, the connector derived its decode-side peer address from the request ID. The request ID was taken unchanged from the client-controlled `X-Request-Id` header. An API caller could therefore name any host and port as the peer, and the prefill worker connected to it and sent the KV cache of the targeted request. Version 0.24.0 removed the connector.

## What was observed

The upstream advisory, published 9 Oct 2026, traces the flaw through four code locations. `OpenAIServing._base_request_id` returned the `X-Request-Id` header unmodified, so client input became the base `request_id` for completion and chat requests. `parse_request_id` in the P2P NCCL connector extracted an `ip` and `port` from that identifier with a permissive regular expression, with no allow-list, scheme check, or block on IP literals. `create_connect` in the NCCL engine then opened a ZMQ connection to the parsed address and sent the NCCL `unique_id` before calling `ncclCommInitRank`. `send_sync` followed by transmitting the KV cache through `ncclSend` over that communicator.

```
# request header (illustrative)
X-Request-Id: <routing token embedding attacker-host:port>
# parse_request_id -> (ip, port) -> create_connect(ip, port)
#   -> NCCL unique_id sent to attacker host -> KV tensors sent via ncclSend
```

The advisory names three consequences: exfiltration of the KV cache for the targeted request, including prompt content and prefix-cached hidden states; disclosure of the NCCL communicator `unique_id`; and a hang of the blocking `ncclCommInitRank` call when the chosen host does not respond. The precondition is a server started with `P2pNcclConnector` and `kv_role` set to `kv_producer`. The attacker needs API access only, which is no credential at all when `--api-key` is unset. No in-the-wild exploitation is reported.

Severity is rated medium. The NVD record scores 8.8, but the vulnerable path exists only in an explicitly configured disaggregated-serving topology, not in a default deployment. Where that topology is present, the data exposed is the prompt state of other users' requests.

## Mitigation

Upgrade to vLLM 0.24.0 or later; the fix (PR #44854) removed the connector and its registration. The advisory lists no workaround. Operators who cannot upgrade should keep prefill workers off any network path reachable by untrusted callers, require an API key, and set the proxy in front of vLLM to overwrite `X-Request-Id` rather than forward it. Identifiers that clients control must never carry routing information; a field that selects a network peer belongs to the operator.
