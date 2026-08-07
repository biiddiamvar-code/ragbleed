---
caseId: "054"
title: "Paperclip's self-registration and import checks chained into unauthenticated remote code execution"
filed: "2026-08-07"
filedDisplay: "07 Aug 2026"
firstObserved: "04 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Paperclip, open-source control plane for AI agent teams (server/CLI tagged 0.3.1, release v2026.416.0 and earlier); network-accessible deployments in \"authenticated\" mode with default open registration, and local deployments in default \"local_trusted\" mode"
cve: "CVE-2026-41679 (unauthenticated RCE via import-authorization bypass, CVSS 10.0); GHSA-x8hx-rhr2-9rf7 (DNS-rebinding RCE against local_trusted mode, CVSS 9.6); GHSA-xfqj-r5qw-8g4j (unauthenticated API routes, CVSS 8.3)"
readTime: "6 min read"
related: ["024", "034", "038"]
---

## Summary

Paperclip is an open-source control plane for running teams of AI agents — it markets itself around the idea of operating a "zero-human company." Oasis Security's research, published 04 August 2026, showed that three separate weaknesses in Paperclip's authorization model chained into unauthenticated remote code execution on any network-accessible instance running default settings, and into drive-by RCE against local development instances via DNS rebinding. All three traced back to the same design property: Paperclip treats an imported agent's configuration file as trusted input, and its process adapter will launch whatever command that configuration names as a child process of the server. Paperclip fixed the chain in v2026.416.0 by requiring instance-administrator rights on company imports and validating request hostnames before assigning identity.

## What was observed

The server-side chain started at account creation. Paperclip's default registration flow accepted new signups with no email verification and no approval step. A freshly registered account could then walk through Paperclip's CLI authorization flow and approve its own pending credential challenge — no separate administrator confirmed the request — which minted a durable, board-level API token entirely under the attacker's control.

That token should not have been enough to create a company from scratch; Paperclip correctly required instance-administrator rights for the direct company-creation path. But the equivalent import route, which accepts a `.paperclip.yaml` bundle describing a new company, its agents, and their configuration, checked only for board-level access. An attacker could submit a bundle defining a new company containing an agent wired to Paperclip's built-in process adapter and a command of the attacker's choosing:

```
# .paperclip.yaml (attacker-supplied import)
# company: new
# agents:
#   - adapter: process
#     command: <attacker-chosen shell command>
#
# import route checks board-level access only —
# not the instance-administrator check company creation enforces
```

Importing the bundle also made the attacker a member of the new company, so when the agent's wakeup endpoint was called next, the standard membership check passed. Paperclip then executed the configured command with the operating-system privileges of its own server process — six API calls total, none requiring an existing account, a victim's interaction, or any credential beyond the one the attack itself had just minted.

A second, independent path reached the same execution primitive without any token at all. Paperclip's default `local_trusted` mode, intended to remove authentication friction during local development, treated every request that reached the service on the loopback interface as an implicit instance administrator — it trusted network location as identity. Oasis demonstrated that DNS rebinding defeats that assumption: a hostname is registered to resolve first to an attacker's server, which serves the malicious JavaScript, then to `127.0.0.1` once the browser has already treated the origin as trusted. Later requests from that same page reached the local Paperclip instance carrying attacker-controlled instructions, and because local mode granted administrator authority based on the loopback address rather than any credential, the server ran the attacker's command with the developer's own privileges — no Paperclip token, cookie, or stolen secret involved.

A third advisory covered several API routes in authenticated mode that never enforced company-scoped access checks at all, including one that disclosed agent-facing skill documentation and deployment/health metadata to unauthenticated callers, and a heartbeat-issue endpoint that would return data to anyone holding a valid run identifier without confirming they belonged to the owning company.

## Mitigation

Upgrade to Paperclip v2026.416.0 or later, which requires instance-administrator access for company imports, enforces company membership on the equivalent existing-company import path, and adds a private-hostname validation guard ahead of the middleware that assigns request identity in `local_trusted` and authenticated deployments alike. Disable open self-registration on any network-accessible instance if it isn't strictly required, since it is the first link in the unauthenticated chain. The broader lesson generalizes past this one product: any system that lets imported or synced configuration control what a server process executes — the same pattern behind case 024's Redis-cache-as-trusted-input and case 034's CrewAI code-interpreter chain — needs to treat that configuration as attacker-reachable input, not administrative intent, the moment the import path is reachable by anyone below full administrator trust.
