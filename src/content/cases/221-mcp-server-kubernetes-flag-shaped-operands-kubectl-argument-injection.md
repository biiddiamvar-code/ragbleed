---
caseId: "221"
title: "mcp-server-kubernetes passed dash-prefixed tool arguments to kubectl as positional operands, letting --filename read files from the server host"
filed: "2026-11-23"
filedDisplay: "23 Nov 2026"
firstObserved: "26 Oct 2026"
severity: medium
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "mcp-server-kubernetes (npm, Flux159/mcp-server-kubernetes, <4.2.0), tools including exec_in_pod, kubectl_patch, kubectl_logs, kubectl_rollout, kubectl_create, explain_resource, node_management and port_forward; fixed in 4.2.0"
cve: "CVE-2026-134817 (GHSA-8v48-c263-r637; CNA: VulnCheck; CWE-88, CVSS 4.0 7.1)"
readTime: "4 min read"
related: ["217", "180", "220"]
---

## Summary

mcp-server-kubernetes builds kubectl command lines from MCP tool arguments. In several tools, values meant to be positional operands, such as a pod or resource name, were placed into the argv without a check for a leading dash, so kubectl parsed them as flags. A client connected over SSE or Streamable HTTP could supply a value such as `--filename=<path>` and have kubectl read files from the host running the server. Version 4.2.0 refuses flag-shaped values in the remaining operand slots.

## What was observed

The fix landed publicly as PR #390, merged on 26 Oct 2026 and shipped in 4.2.0 the same day; CVE-2026-134817 was published by VulnCheck on 22 Nov 2026, crediting Zachariah Mithani of AploSec. The advisory cites `src/tools/exec_in_pod.ts` at v4.1.9 and names `exec_in_pod`, `kubectl_patch` and `kubectl_logs` as examples.

The server already had two defences. `assertSafeArgv` rejected specific dangerous flags, but the PR stated that it "only refuses the flags it knows about." An earlier change, PR #369, had added an `assertNotFlagLike` check to the positional slots of `kubectl_get`, `kubectl_describe`, `kubectl_delete`, `kubectl_scale` and `kubectl_generic`. The other tools still forwarded operand values unchecked. Because kubectl, like most CLI parsers, treats any argument beginning with `-` as an option regardless of where the caller intended it to sit, a name field became a flag field.

```
# tool call: kubectl_logs  { "name": "--filename=/root/.kube/config", ... }
# argv built: kubectl logs --filename=/root/.kube/config ...
#              ^ operand slot, parsed by kubectl as an option
```

The fix's own regression test used exactly that value, `--filename=/root/.kube/config`, and expected a rejection in every slot. The kubeconfig is the file that holds the server's cluster credentials. PR #390 added `assertNotFlagLike` to `exec_in_pod` (name), `kubectl_patch` (resourceType, name), `kubectl_rollout` (subCommand, resourceType, name), `kubectl_logs` (name), `kubectl_create` (name, secretType, serviceType), `explain_resource` (resource), `node_management` (nodeName) and `port_forward` (resourceType). Value-taking flags such as `-n` and `-c` were unaffected. The fix rejects leading-dash values outright; no `--` end-of-options delimiter was added.

The arguments in question are the ones a language model fills in when an agent calls the tool, so the input reaches kubectl from whatever text steered the model as well as from a directly connected client. The advisory scopes the attack to remote clients on the HTTP transports.

Severity is rated medium, below the CVSS 7.1 headline. Exploitation required a client session on a network transport rather than local stdio, and the read was limited to files the server process could access, though those included its own cluster credentials.

## Mitigation

Upgrade mcp-server-kubernetes to 4.2.0 or later. The release also bundles related hardening: a verb policy for `kubectl_generic` (#387), fail-closed argv checks (#388), `kubectl_create` input validation (#389), private temp files (#391) and disabling `kubectl_context set` in read-only mode (#392). Prefer the stdio transport for local agent use; where an HTTP transport is required, put authentication in front of it and do not expose it beyond the hosts that need it. If an affected version was reachable over SSE or HTTP, rotate the kubeconfig credentials on the host.

A blocklist of known-bad flags never covers the flags it did not list. The operand slot has to refuse anything that looks like a flag.
