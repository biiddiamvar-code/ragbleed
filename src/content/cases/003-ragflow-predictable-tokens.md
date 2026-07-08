---
caseId: "003"
title: "RAGFlow's shared token generator let a public share link unlock a full account"
filed: "2026-01-06"
filedDisplay: "06 Jan 2026"
firstObserved: "31 Dec 2025"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "RAGFlow (versions prior to 0.22.0)"
cve: "CVE-2025-69286"
readTime: "5 min read"
related: ["002", "001", "005"]
---

## Summary

RAGFlow generated two very different kinds of credentials — a user's personal API key, and the "beta" token used to authenticate a shared agent or assistant link — through the same serializer, fed with predictable inputs. Because both were derived from the same source, anyone holding the second, low-stakes credential could work backward to the first, high-stakes one.

## What was observed

Sharing an agent or assistant in RAGFlow generates a public link, protected by a beta token, so other people can use the agent without logging in. That token was never meant to grant any broader access. The problem was in how it was generated: both the beta token and the account owner's personal API key came out of the same `URLSafeTimedSerializer` instance, seeded with predictable inputs rather than independent, cryptographically random ones.

```
# both derived from the same serializer + seed
personal_api_key = URLSafeTimedSerializer(seed).dumps(payload_a)
beta_share_token  = URLSafeTimedSerializer(seed).dumps(payload_b)
# beta_share_token is public by design → api_key is derivable
```

That shared, predictable origin meant the two tokens weren't just similar in format — they were mutually derivable. Anyone who obtained a shared agent URL, which by design is meant to be handed out freely, could compute the account owner's personal API key from it. That key gave full control over the account: its agents, its data, anything reachable through the API.

## Mitigation

Upgrade to RAGFlow 0.22.0 or later, where API keys and beta tokens are generated with independent serializers and non-predictable inputs. If you've shared agent or assistant links from a pre-0.22.0 instance, treat the associated account's API key as potentially compromised and rotate it after upgrading — the fix prevents new derivations, but doesn't retroactively invalidate a key someone may have already computed.
