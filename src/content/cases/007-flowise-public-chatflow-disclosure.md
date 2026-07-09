---
caseId: "007"
title: "Flowise's public chatflow endpoint returned everything, including credentials"
filed: "2026-04-26"
filedDisplay: "26 Apr 2026"
firstObserved: "23 Apr 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Flowise (versions through 3.0.13; sanitization missing entirely from the 3.0.13 Docker image)"
cve: "CVE-2026-41278"
readTime: "4 min read"
related: ["006", "003", "002"]
---

## Summary

Flowise lets you publish a chatflow publicly so anyone can use it without logging in. The endpoint backing that feature, `GET /api/v1/public-chatflows/:id`, was supposed to strip sensitive fields before returning the chatflow's configuration. It didn't — anyone who could reach a public chatflow's URL could pull back the entire underlying object, credential IDs and plaintext API keys included.

## What was observed

A public chatflow is meant to expose only what's needed to run it: the conversation interface, not the wiring behind it. The endpoint that serves that public view returns the chatflow's full stored object, and the responsibility for removing anything sensitive from that object sat entirely with a single sanitization step before the response went out.

That step was supposed to be a function called before the response left the server. Testing against the released 3.0.13 Docker image showed the function wasn't present in that build at all — not misconfigured, not partially applied, simply absent. Both `public-chatflows` and the related `public-chatbotConfig` endpoint returned completely raw `flowData`: credential IDs, plaintext API key fields, and password-type configuration values, all in the same response a normal visitor's browser gets when loading the public chat widget.

Because public chatflows are a standard, commonly used feature — not an edge case or a misconfiguration someone opted into — this was exposed by default wherever the feature was used as intended. No authentication, no special request, nothing beyond knowing a chatflow's public ID, which is often visible directly in the embed URL.

## Mitigation

Upgrade to Flowise 3.1.0 or later, which restores proper sanitization of sensitive fields before the response is returned. Until upgraded, treat any credential referenced by a public chatflow as exposed: rotate the associated API keys and any downstream service credentials, since a leaked key is not something a version upgrade retroactively invalidates. If public chatflows can't be upgraded immediately, restrict access to `/api/v1/public-chatflows/` and `/api/v1/public-chatbotConfig/` at the network or reverse-proxy level as a stopgap.
