---
caseId: "036"
title: "LMDeploy's vision-language image loader turned an image URL into a path to cloud credentials"
filed: "2026-07-29"
filedDisplay: "29 Jul 2026"
firstObserved: "18 Apr 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LMDeploy (all versions <=0.12.2; fixed in 0.12.3)"
cve: "CVE-2026-33626"
readTime: "4 min read"
related: ["010", "015", "021"]
---

## Summary

LMDeploy is Shanghai AI Laboratory's toolkit for serving vision-language and text LLMs, built around InternLM's multimodal model family. Its vision-language image loader fetched whatever URL a caller placed in an `image_url` field, with no check on whether that URL pointed at a private or link-local address, and the API server bound to `0.0.0.0` with authentication disabled by default. A request that claimed to be asking the model to describe an image could instead point the server at its own cloud metadata endpoint and receive back credentials. The flaw was exploited against internet-facing honeypots within roughly 12 hours of public disclosure.

## What was observed

The `load_image()` function in `lmdeploy/vl/utils.py` took a URL string, checked only that it started with `http`, and passed it directly to `requests.get()`. `encode_image_base64()`, used on the same code path, had the identical gap. Neither function checked the resolved address against loopback, link-local, or private-network ranges before the request left the server.

```
# lmdeploy/vl/utils.py — load_image()
# if image_url.startswith('http'):
#     response = requests.get(image_url, ...)
#     # no check that the resolved IP isn't 127.0.0.1, 169.254.x.x, 10.x.x.x, etc.
```

Two default settings widened the blast radius past a typical unvalidated-fetch bug. The API server bound to `0.0.0.0` by default rather than localhost, and API key authentication was off by default — meaning most LMDeploy deployments accepted the request from any client that could reach the port at all, not just an authenticated one. A request naming a model like `internlm-xcomposer2` with `image_url` set to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` was fetched exactly like a real image would be, and the metadata response came back through the normal vision pipeline.

Sysdig's honeypot fleet recorded the first live exploitation attempt 12 hours and 31 minutes after the advisory went public. Over a single eight-minute session, the attacker used the image loader as a generic SSRF primitive to port-scan the network behind the model server — probing AWS instance metadata, Redis, MySQL, a secondary HTTP admin interface, and an out-of-band DNS exfiltration endpoint — treating the vision endpoint as an internal network scanner rather than a way to steal any one specific secret.

## Mitigation

Upgrade to LMDeploy 0.12.3 or later, which validates image URLs against private and link-local address ranges before fetching. Where upgrading isn't immediate, don't bind the API server to `0.0.0.0` without authentication enabled, and block egress from the inference host to metadata endpoints and internal service ports at the network layer as a backstop. The broader lesson holds across every framework that lets a model "look at" a URL: an image loader, a document fetcher, and a webhook caller are all the same SSRF primitive wearing different clothes, and validating the content type of what comes back does nothing to stop the request from reaching an internal address in the first place.
