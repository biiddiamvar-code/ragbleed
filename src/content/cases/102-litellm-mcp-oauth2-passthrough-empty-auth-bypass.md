---
caseId: "102"
title: "LiteLLM's MCP OAuth2 fallback swapped a failed key check for an empty, always-valid auth object"
filed: "2026-09-04"
filedDisplay: "04 Sep 2026"
firstObserved: "30 Jun 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LiteLLM proxy/AI gateway, MCP Streamable HTTP endpoint with OAuth2 passthrough for upstream MCP servers (versions <1.84.0)"
cve: "CVE-2026-59822 (GHSA-7488-6r32-c95q); added to CISA KEV catalog 02 Sep 2026"
readTime: "5 min read"
related: ["028", "057", "017"]
---

## Summary

LiteLLM is an open-source AI gateway that many organizations put in front of every model provider they use, and it exposes an MCP Streamable HTTP endpoint so clients can open sessions against whatever MCP tool servers the gateway has configured. That endpoint validated a caller's LiteLLM API key on every request, but it also supported OAuth2 passthrough for upstream MCP servers that manage their own authentication. When LiteLLM's own key check failed, the passthrough fallback didn't reject the request — it substituted an empty, unauthenticated auth object and let the request proceed as if it had succeeded. Any request carrying a fabricated `Authorization` header could reach configured MCP tools with no valid LiteLLM key at all. CISA added the flaw, tracked as CVE-2026-59822, to its Known Exploited Vulnerabilities catalog on 2 September 2026 after confirming active exploitation, with a federal remediation deadline of 16 September.

## What was observed

The MCP auth handler's job was straightforward: pull the Bearer token off the request, validate it against LiteLLM's key store, and pass the resulting identity down to whatever MCP tooling the request wanted to reach. The complication was OAuth2 passthrough — a legitimate feature letting an upstream MCP server accept its own credentials rather than a LiteLLM-issued key. To accommodate that case, the handler's fallback path caught a failed key validation and, instead of returning 401, constructed an empty `UserAPIKeyAuth()` object and continued.

```
# MCP auth handler, illustrative
auth = validate_litellm_key(bearer_token)
if auth is None and mcp_server.supports_oauth2_passthrough:
    auth = UserAPIKeyAuth()   # empty object — not a rejection
# downstream authorization only checks "is auth present", not "is it valid"
proceed_with_mcp_session(auth)
```

Downstream authorization logic treated the presence of an auth object as sufficient evidence of a valid session; it never distinguished an empty, fallback-constructed object from one carrying a real, validated identity. That meant the fallback branch didn't need a real OAuth2 token to satisfy it — any string in the `Authorization` header, valid or not, would fail LiteLLM's own key check and land in the same branch that manufactured an empty-but-accepted auth object. A successful request could enumerate configured MCP tools, invoke them, and reach whatever internal services, repositories, or databases those tools connected to. GitHub's advisory rated confidentiality impact high and required no prior privileges and no user interaction to trigger. The fix, shipped in LiteLLM 1.84.0, is a separate patch floor from the 1.83.0 release that closed an unrelated admin-API authorization bug (CVE-2026-35029) two months earlier — operators who upgraded only that far remained exposed to this one.

> A fallback built to accommodate a server that authenticates its own way ended up trusting the absence of a valid key as though it were the presence of one.

## Mitigation

Upgrade LiteLLM to 1.84.0 or later — 1.83.0 alone is not sufficient, since it addresses a different vulnerability. Where immediate upgrade isn't possible, disable or block MCP routes at the reverse proxy or API gateway until patched, and restrict administrative and MCP control surfaces to trusted networks separately from normal inference traffic. Because the flaw grants access to whatever MCP tools were configured, inventory those tools' permissions and rotate any credentials — model-provider keys, database connection strings, repository tokens — that a connected MCP integration could reach, particularly if MCP endpoints were reachable from untrusted networks before patching. The broader lesson: an authentication fallback designed for one legitimate edge case (an upstream server with its own auth) has to fail closed on every other path into it, not substitute a placeholder object that downstream code can't distinguish from a real, validated session.
