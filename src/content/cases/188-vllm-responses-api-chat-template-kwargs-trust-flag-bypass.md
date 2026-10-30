---
caseId: "188"
title: "vLLM /v1/responses accepted request-supplied chat_template in chat_template_kwargs without the trust_request_chat_template check"
filed: "2026-10-30"
filedDisplay: "30 Oct 2026"
firstObserved: "26 Oct 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (>=0.16.0, <0.32.0), OpenAI-compatible /v1/responses endpoint"
cve: "CVE-2026-115918 (GHSA-x567-49g5-p4cf, CWE-400, CWE-770)"
readTime: "3 min read"
related: ["121", "029", "117"]
---

## Summary

vLLM protects its Chat Completions path by refusing a request-supplied Jinja chat template unless the operator starts the server with `--trust-request-chat-template`. The Responses API path did not apply that check to `chat_template_kwargs`. An authenticated caller could therefore pass a template through `/v1/responses` on a default configuration. The fix shipped in vLLM 0.32.0.

## What was observed

The advisory GHSA-x567-49g5-p4cf, with NVD publication on 26 Oct 2026, describes the `/v1/responses` endpoint accepting request-level `chat_template_kwargs`. When no server-side chat template was configured and the trust flag was left at its default (disabled), a `chat_template` value inside those kwargs was kept by `ChatParams.get_apply_chat_template_kwargs()` and passed to the renderer. The trust policy enforced on the other endpoints was not enforced on this one.

The impact recorded is denial of service through CPU or memory exhaustion during Jinja rendering (CWE-400, CWE-770), scored 6.5 (CVSS 3.1, AV:N/AC:L/PR:L/A:H). The advisory presents the flaw as a sibling of two earlier vLLM advisories, GHSA-6fvq-23cw-5628 and GHSA-69j4-grxj-j64p, which covered older Chat Completions and tokenize code paths. The cost of rendering a template depends on what the template instructs, not on the size of the request that carries it (see case 121 for the mechanism).

```
# Request shape (illustrative, no payload)
# POST /v1/responses
# { ..., "chat_template_kwargs": { "chat_template": "<jinja source>" } }
# default config: trust flag off, no server template -> value was rendered
```

The sources disagree on the affected range. The OSV record lists 0.16.0 through 0.31.0, while the report body suggests 0.16.0 through 0.23.0. The range in the front matter follows the OSV record and the fixed version; the narrower claim was not independently confirmed.

Severity is rated medium: an authenticated caller is required, and the outcome is loss of availability, but self-hosted vLLM is often exposed with minimal authentication, which lowers that bar in practice.

## Mitigation

Upgrade vLLM to 0.32.0 or later. The recommended fix rejects `chat_template_kwargs["chat_template"]` when the trust flag is off while leaving ordinary kwargs such as `enable_thinking` working. Until upgraded, restrict `/v1/responses` to trusted callers at the gateway, or strip `chat_template_kwargs` from untrusted requests. A security control added to one endpoint of a multi-endpoint server has to be applied to every path that reaches the same sink.
