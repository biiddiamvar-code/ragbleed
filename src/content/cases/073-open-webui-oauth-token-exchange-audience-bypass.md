---
caseId: "073"
title: "Open WebUI's OAuth token exchange endpoint accepted access tokens issued to any other client on the same identity provider"
filed: "2026-08-18"
filedDisplay: "18 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.8.0, <0.11.0), OAuth token exchange endpoint (requires ENABLE_OAUTH_TOKEN_EXCHANGE=True)"
cve: "CVE-2026-70482 (GHSA-rq84-p6rr-vf89)"
readTime: "5 min read"
related: ["035", "008", "016"]
---

## Summary

Open WebUI ships an optional OAuth token exchange endpoint that lets a client hand over an already-obtained provider access token and receive an Open WebUI session in return, instead of running the full OAuth redirect flow through Open WebUI itself. The endpoint validated an incoming token only by asking the identity provider's userinfo endpoint whether the token was live — never checking which application the token had actually been issued for. Because a userinfo endpoint answers "is this token valid" rather than "was this token issued for you," a token minted by the same identity provider for a completely different, unrelated application was just as good as one minted for Open WebUI, letting a token stolen or phished from a lower-value app grant access to a victim's Open WebUI account.

## What was observed

The vulnerable route, `/oauth/{provider}/token/exchange`, is reachable only when an operator sets `ENABLE_OAUTH_TOKEN_EXCHANGE=True` — a feature meant for native or single-page-application clients that already hold a provider access token and want to hand it to Open WebUI's backend directly. On receiving a token, the handler called the provider's standard userinfo endpoint to confirm the token was valid and to look up the associated identity, then created a session for that user. Nothing in the flow checked the token's audience.

OAuth access tokens are ordinarily scoped to the client application (`client_id`) that requested them, and OpenID Connect's `aud` claim exists specifically so a relying party can confirm a token was issued for it before trusting it — the provider's token-introspection endpoint reports this; its userinfo endpoint does not. Open WebUI's exchange handler used the endpoint that omits this information:

```
# illustrative: token exchange endpoint, pre-fix
POST /oauth/{provider}/token/exchange
  token = request.body.access_token
  userinfo = provider.get_userinfo(token)   # confirms token is *valid*, not who it's for
  session = create_session(userinfo.sub)    # any client's token accepted as any client's token
```

In a common enterprise SSO topology — one identity-provider tenant (Okta, Azure AD, a generic OIDC provider, "Sign in with Google") backing several unrelated internal or third-party applications — this meant a token issued for a marketing site's login button, an internal wiki, or any other app registered against the same tenant was accepted just as readily as a token issued for Open WebUI's own registration. A token obtained through phishing, an XSS bug, or simple leakage from the weakest application sharing that identity-provider tenant became a valid credential for the strongest one: Open WebUI, which holds chat history, uploaded documents, and connected AI-provider API keys.

## Mitigation

Fixed in Open WebUI 0.11.0, which validates the token's audience against Open WebUI's own registered client before establishing a session. Operators who have set `ENABLE_OAUTH_TOKEN_EXCHANGE=True` should upgrade immediately; deployments that never enabled the exchange flow are unaffected regardless of version. This site rates the mechanism medium rather than matching the advisory's CVSS 8.1: reaching the endpoint requires an operator to have opted into a non-default feature, and exploiting it requires an attacker to already possess a token issued by the shared identity provider, not bare unauthenticated network access. Where the feature is enabled, the underlying lesson holds regardless of severity score: any service accepting a bearer token from an external identity provider needs to validate the token's audience against its own client registration — confirming a token is valid is a different check from confirming it was meant for you, and providers expose a different endpoint for each.
