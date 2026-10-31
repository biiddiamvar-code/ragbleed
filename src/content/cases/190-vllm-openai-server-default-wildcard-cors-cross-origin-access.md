---
caseId: "190"
title: "vLLM's OpenAI-compatible server defaulted to wildcard CORS origins, exposing unauthenticated instances to any web page"
filed: "2026-10-31"
filedDisplay: "31 Oct 2026"
firstObserved: "20 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (all versions with default configuration, fixed in 0.32.0), OpenAI-compatible HTTP server"
cve: "CVE-2026-115917 (GHSA-vvpg-rrww-wpmh, CWE-942)"
readTime: "3 min read"
related: ["139", "047", "188"]
---

## Summary

The vLLM OpenAI-compatible server set its default allowed CORS origins to a wildcard and passed it to Starlette's `CORSMiddleware`. A web page opened in a browser that could reach a vLLM server could therefore make cross-origin requests to it and read the responses. Servers running without an API key, on localhost, an internal network, or a VPN, were exposed through the visitor's browser. The fix shipped in vLLM 0.32.0.

## What was observed

The advisory GHSA-vvpg-rrww-wpmh, published 20 Oct 2026, records the default `allowed_origins` as `["*"]`. Authentication is enforced only when `--api-key` or `VLLM_API_KEY` is set, so a default deployment accepted requests from any origin. The default `allow_credentials=False` blocked cookie-based cross-origin requests, which removed the CSRF variant. It did not block reading responses, because the wildcard origin was permitted to do so.

The documented consequences were listing models, sending chat completion requests, consuming GPU time, and reading model output. The browser acted as the network proxy, which placed servers that were never exposed to the internet within reach of any page the operator or a colleague opened. Endpoints under `/v1`, `/v2`, `/inference`, and `/cohere` required a key when one was configured and were open when it was not.

The advisory rates the issue low (CVSS 3.1 of 3.4), and NVD scores it 4.7. Severity is rated medium here: the setting was the default, and the data readable through it is whatever the served model returns, including content drawn from private context or system prompts in a RAG deployment. Servers with a bearer key were exposed only to an attacker already holding a valid token.

## Mitigation

Upgrade vLLM to 0.32.0 or later. On earlier versions, set `--api-key`, restrict the `--allowed-origins` option to named origins, and keep the server off networks that browsers can reach, or put it behind an authenticating reverse proxy. An inference server on a private network is still reachable by every browser on that network, and its defaults should be treated accordingly.
