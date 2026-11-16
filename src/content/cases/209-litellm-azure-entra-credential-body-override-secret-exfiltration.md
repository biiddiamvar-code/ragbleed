---
caseId: "209"
title: "LiteLLM's request-body blocklist omitted Azure Entra credential parameters, letting a caller point client_id at a server-side secret and read it back in the authentication error"
filed: "2026-11-16"
filedDisplay: "16 Nov 2026"
firstObserved: "12 Nov 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "litellm proxy (<1.106.9; release lines patched in 1.106.9, 1.108.6, 1.109.1 and 1.110.0-rc.2), only with at least one azure/ or azure_ai/ model and no AZURE_API_KEY or AZURE_OPENAI_API_KEY environment variable"
cve: "No CVE assigned as of writing; tracked as GHSA-2rwg-2wh4-7c4f (CWE-184 / CWE-209, CVSS 3.1 7.7)"
readTime: "4 min read"
related: ["204", "183", "158"]
---

## Summary

The LiteLLM proxy filters request bodies against a blocklist of parameters that callers must not set, because some provider parameters override server-held credentials. The six Azure Entra ID parameters were not on it. An authenticated low-privilege user could supply them in an ordinary completion or image request, set `client_id` to a reference that the proxy resolved from its own environment, and receive the resolved value back inside Entra's rejection message. The master key was one of the values reachable this way.

## What was observed

GitHub advisory GHSA-2rwg-2wh4-7c4f was published on 12 Nov 2026. It lists patched releases on four lines: 1.106.9, 1.108.6, 1.109.1 and 1.110.0-rc.2. No reporter credit or CVE was attached at publication.

Per the advisory, the omitted parameters were `tenant_id`, `client_id`, `client_secret`, `azure_username`, `azure_password` and `azure_scope`. Sent in the body of `POST /v1/chat/completions` or `POST /v1/images/generations` for an Azure deployment, they replaced the credential that deployment would otherwise use. The proxy resolves references to environment variables when it reads credential values, and it applied that resolution to the caller-supplied fields as well. Entra then attempted to authenticate an application whose identifier was the resolved secret, rejected it as unknown, and the proxy relayed the error, with the value in it, to the caller.

```
# Illustrative
POST /v1/chat/completions                       # low-privilege virtual key
{ "model": "azure/<deployment>",
  "tenant_id": "<any>",
  "client_id": "<reference to LITELLM_MASTER_KEY>",
  "client_secret": "<any>", ... }
# proxy resolves client_id server-side -> Entra: unknown application '<resolved value>'
# error returned verbatim to caller
```

Two weaknesses combined. The blocklist was incomplete for one provider's credential surface (CWE-184), and upstream authentication errors were returned without redaction (CWE-209). The advisory states the same reference mechanism reached files named by an environment variable, and that on a typical deployment the readable values included the database connection URL, provider API keys and `LITELLM_MASTER_KEY`. Holding the master key gives full administrative control of the proxy.

The preconditions narrowed the population. The proxy had to serve at least one `azure/` or `azure_ai/` model, and the Azure key environment variables had to be unset, which is the case where credentials live in per-deployment configuration or Entra is used instead of keys. The caller needed only a virtual key with access to one such model.

The rating is high. The configuration is ordinary for organisations fronting Azure OpenAI with LiteLLM, the privilege required is the lowest the proxy issues, and the data exposed is the gateway's root credential and every secret in its environment.

## Mitigation

Upgrade to 1.106.9, 1.108.6, 1.109.1 or 1.110.0-rc.2 according to the release line in use. Until then, strip the six parameters from request bodies at a reverse proxy or API gateway in front of LiteLLM, as the advisory recommends. Operators who served Azure models to untrusted virtual-key holders on an affected version should rotate the master key, the database credentials and all provider keys, and review proxy logs for completion requests carrying Entra parameters.

A denylist over provider parameters has to be complete for every provider the proxy supports, and each new provider adds to it. Server-side secret resolution should never apply to values that arrived in a request body.
