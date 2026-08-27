---
caseId: "086"
title: "NemoClaw's Windows-host Ollama path skipped the loopback proxy, and DNS rebinding could poison the model's chat template"
filed: "2026-08-27"
filedDisplay: "27 Aug 2026"
firstObserved: "25 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "NVIDIA NemoClaw, Windows-host and WSL/Docker Desktop configuration paths (non-WSL macOS/Linux fixed in v0.0.35); Ollama local inference backend"
cve: "No CVE assigned; reported directly to NVIDIA PSIRT by Oasis Security, no CVE requested"
readTime: "5 min read"
related: ["054", "020", "035"]
---

## Summary

NemoClaw is NVIDIA's open source reference stack for running agent harnesses such as OpenClaw inside its OpenShell sandboxes, with Ollama as one of its supported local inference backends. On most platform paths, NemoClaw keeps Ollama bound to loopback behind a token-gated proxy. On the Windows-host path — the configuration NVIDIA's own documentation uses so that Docker Desktop containers can reach the daemon — NemoClaw instead starts Ollama with `OLLAMA_HOST=0.0.0.0:11434` and does not run that proxy at all. Oasis Security showed that a malicious webpage, using DNS rebinding, could reach that unauthenticated API from a victim's own browser and rewrite the model's chat template, planting hidden instructions that apply to every later conversation regardless of what system prompt the agent itself supplies. NVIDIA fixed the non-Windows paths in NemoClaw v0.0.35; as of the August 25, 2026 disclosure, the Windows-host and WSL paths remained unaddressed.

## What was observed

Ollama's API has been a DNS-rebinding target before: NCC Group disclosed CVE-2024-28224 in April 2024, and Ollama's v0.1.29 fix added a Host-header check to reject requests whose Host does not match an authorized value. That check has a carve-out, though — it only runs when the daemon is bound to loopback. Bind Ollama to `0.0.0.0`, and the Host check is skipped entirely, exactly the configuration NemoClaw's Windows-host path sets up so a Docker Desktop container can reach the host daemon.

With the Host check absent, the remaining defense is Cross-Origin Resource Sharing. That defense assumes a browser-originated request carries an `Origin` header that differs from the server's own address. DNS rebinding defeats the assumption: the attacker's domain first resolves to their own server, which returns the malicious page, and then — once the browser has already committed to treating later requests as same-origin — resolves to `127.0.0.1`. The browser keeps sending requests to what it believes is the same origin it started with, and Ollama's CORS layer sees an `Origin` and `Host` that both nominally belong to the attacker's domain, since the DNS trick makes the loopback address answer for it.

```
# illustrative — the payload write, not an exploit
POST /api/create HTTP/1.1
Host: attacker-controlled-domain.example   (resolves to 127.0.0.1 via rebinding)

{
  "model": "victims-model",
  "template": "{{ .System }}\n<hidden directive appended here>\n{{ .Prompt }}"
}
```

The `/api/create` endpoint accepts a new chat template outright. A template controls how the structured messages array — system prompt, user turns, tool outputs — gets flattened into the raw text the model actually sees. A poisoned template can append attacker text to every system message before inference runs, and that text is invisible to any client inspecting the conversation, because the template is a model-level property, not something carried in the messages themselves. Oasis Security's researcher, Elad Luz, tested the full chain on macOS with Firefox against a vulnerable NemoClaw build and noted the obvious consequence: "the client cannot detect or prevent this." Once planted, the instructions persist across sessions and survive the agent supplying its own system prompt on every new conversation — the poisoning happens one layer below where the agent's own prompt hygiene can reach it.

> Sandboxing protects the endpoint. It does not protect the model running behind it.

NemoClaw introduced a bind-probe default in v0.0.106 (August 10, 2026) that refuses to start its local proxy against a non-loopback Ollama backend, but that check runs inside a proxy process the Windows-host and WSL paths never launch in the first place — the fix doesn't reach the platform configuration where the exposure exists.

## Mitigation

Set `OLLAMA_HOST=127.0.0.1:<port>` on the Ollama service directly rather than relying on NemoClaw's platform defaults, and route container access through an explicit token-gated proxy instead of a wide-open bind. Where the Windows-host or WSL path must be used, keep the host off networks reachable by an untrusted browser tab, since the rebinding attack runs from the browser already present on the host and does not require inbound network exposure. Operators running any locally-hosted inference backend should periodically diff the chat template returned by `/api/show` against a known-good copy — NemoClaw does not do this today, querying that endpoint only for context length and tool-calling capability, which means a poisoned template currently has no built-in integrity check anywhere in the stack watching for it.
