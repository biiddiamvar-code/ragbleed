---
caseId: "059"
title: "A Linux page-cache bug let Claude Cowork's sandboxed agent read and write the entire host Mac"
filed: "2026-08-09"
filedDisplay: "09 Aug 2026"
firstObserved: "23 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disputed"
affectedSystems: "Claude Cowork macOS desktop app, local (non-cloud) execution mode, prior to cloud execution becoming the default; underlying Ubuntu guest kernel vulnerable to CVE-2026-46331"
cve: "CVE-2026-46331 (\"pedit COW\", the underlying Linux kernel net/sched bug); the escape chain itself carries no separate CVE — disclosed as \"SharedRoot\" by Accomplish AI, reported to Anthropic and closed as Informative"
readTime: "6 min read"
related: ["002", "053", "034"]
---

## Summary

Security researchers at Accomplish AI demonstrated that untrusted content processed by a local Claude Cowork session could escape the Linux virtual machine the agent runs in and reach the host Mac's entire filesystem, including SSH keys and cloud credentials, with no permission prompt at any step. The escape chained an intentionally permissive sandbox configuration — unprivileged user namespaces left enabled, a default-allow seccomp filter, and the full host filesystem mounted read-write into the VM — with a public June 2026 Ubuntu kernel bug to obtain root inside the guest, then walked out through the shared mount. Anthropic's security team closed the report as Informative rather than shipping a targeted fix; the product has since moved to cloud execution by default, which sidesteps the local-VM attack surface, but Cowork sessions still run in the affected local configuration when a user opts into it.

## What was observed

Cowork's local execution model runs the desktop app under the logged-in macOS user while the agent's actual work happens inside a Linux VM created through Apple's Virtualization framework. Each session gets a disposable unprivileged user wrapped in a seccomp filter, and folders the user connects are brokered into the VM as mounts by a root-owned daemon, `coworkd`. Separately from those per-folder mounts, the entire host filesystem is also mounted read-write into the VM, visible only to a process with root inside the guest, at a fixed path.

The chain to reach that mount ran through six steps. The unprivileged session user first called `unshare` to create a new user namespace, a permitted operation that made it root within that namespace and granted the full set of Linux capabilities, including `CAP_NET_ADMIN`, with no exploit required. That capability let it configure a traffic-control action using the kernel module `act_pedit`, reachable over a netlink socket the seccomp filter allowed; merely referencing the module caused the kernel to autoload it. On this guest kernel, `act_pedit` carried CVE-2026-46331 ("pedit COW"), a bug disclosed against Ubuntu in June 2026 that let an unprivileged caller poison the page cache of a file it could read but not write — without altering the file on disk. The session user used that primitive against a root-owned helper binary that `coworkd` periodically re-executes; because `coworkd` runs as root, the exec of the poisoned cached copy carried no privilege boundary for `NoNewPrivs` to enforce, handing the session user root inside the guest. Guest-root could then see and write the host-wide mount, reaching the Mac's filesystem directly as the logged-in desktop user.

```
# shape of the chain, not exploit code
unshare(new_user_namespace)              # unprivileged; grants CAP_NET_ADMIN in-namespace
configure_tc_action(act_pedit)           # netlink socket allowed by seccomp; autoloads module
poison_pagecache(root_owned_helper)      # CVE-2026-46331, read-only file, cache only
wait_for_coworkd_reexec(helper)          # coworkd runs as root -> guest-root
access("/mnt/.virtiofs-root/...")        # entire host filesystem, read-write
```

Four independent design choices made the chain possible, and any one of them closing would have stopped it regardless of the specific kernel bug: unprivileged user namespaces were left enabled rather than disabled at the sysctl level; the seccomp filter defaulted to allow rather than to an address-family and syscall allowlist; nothing prevented autoloading of networking modules the sandbox never needed; and the host filesystem was shared into the VM in full and read-write rather than scoped to the folders a session actually connected. Anthropic's review treated the kernel bug's freshness as grounds to close the report as Informative and read the four hardening measures as defense-in-depth rather than a standalone vulnerability. The researchers' broader point is that this framing understates the risk: kernel privilege-escalation bugs in networking and I/O subsystems surface on a regular cadence, and the gap between a fix landing upstream and a public exploit has collapsed to hours, so a guest kernel is structurally never caught up. Each of the four design choices, unlike a kernel patch, closes an entire category of future escape rather than one CVE.

## Mitigation

Cowork's shift to cloud execution as the default removes the local-VM attack surface for most users going forward, but anyone running local sessions remains exposed to this chain or a successor using a different kernel bug in the same subsystem. For any product architecture that shares a host filesystem into a guest VM for a sandboxed agent: disable unprivileged user namespaces (`kernel.unprivileged_userns_clone=0` or the AppArmor equivalent), replace default-allow seccomp filters with an allowlist that blocks `unshare`, `setns`, `clone3`, and `AF_NETLINK` sockets, block autoloading of unused kernel modules with `install ... /bin/false`, and scope any host-to-guest filesystem share to the specific directories a session was granted rather than the entire host. That last change matters most: it means a full guest-root compromise has nowhere to land. Treating a VM boundary as sufficient containment for untrusted agent input assumes the guest kernel is current against a fast-moving supply of privilege-escalation bugs — an assumption that doesn't hold indefinitely for any given image.
