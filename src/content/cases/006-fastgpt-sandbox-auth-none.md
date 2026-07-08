---
caseId: "006"
title: "FastGPT's agent sandbox shipped with authentication turned off"
filed: "2026-05-09"
filedDisplay: "09 May 2026"
firstObserved: "08 May 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "FastGPT, agent-sandbox component (versions 4.14.10 to <4.14.13)"
cve: "CVE-2026-42302"
readTime: "4 min read"
related: ["002", "003", "001"]
---

## Summary

FastGPT's agent-sandbox — the component that runs code on behalf of a workflow — starts a full VS Code web IDE (`code-server`) with authentication explicitly disabled and bound to every network interface. Anyone who could reach the container's port got a working terminal inside the sandbox with no login step at all.

## What was observed

The sandbox is meant to be an isolated place for agent workflows to execute code. Its startup script launched that environment like this:

```
# projects/agent-sandbox/entrypoint.sh
exec code-server --bind-addr 0.0.0.0:8080 --auth none ./
```

Two decisions here compound each other. `--auth none` removes the password prompt code-server normally requires. `--bind-addr 0.0.0.0:8080` makes the service reachable from outside the container rather than only from localhost. Individually, either one narrows the exposure to something more containable — internal-only access with no login, or a login prompt reachable from the network. Together, they mean: whoever can route a packet to port 8080 gets a fully working development environment, complete with an integrated terminal, no credentials needed.

That's a meaningfully different failure from a code-injection bug. There was no filter to slip past and no payload to craft — the front door simply had no lock on it. In containerized deployments where this port ends up exposed via Docker port mapping, a Kubernetes NodePort, or a misconfigured firewall rule, the sandbox is available to anyone who finds it.

## Mitigation

Upgrade to FastGPT 4.14.13 or later, which removes both flags from the startup script. Independently of the patch, treat any code-execution sandbox as a service that needs its own authentication and network exposure review — don't assume that "it's just a sandbox" means a missing login prompt is low-stakes. Audit container and orchestration configs for this deployment specifically to confirm port 8080 isn't reachable from outside the internal network.
