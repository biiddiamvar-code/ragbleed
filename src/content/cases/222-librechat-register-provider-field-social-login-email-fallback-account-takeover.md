---
caseId: "222"
title: "LibreChat's registration endpoint persisted a caller-supplied provider field, and social login matched it by email without checking the OAuth subject, binding an attacker's password to the victim's account"
filed: "2026-11-24"
filedDisplay: "24 Nov 2026"
firstObserved: "17 Nov 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "LibreChat (>=0.7.0, <0.8.6), local registration enabled with at least one social login provider configured"
cve: "CVE-2026-54039 (GHSA-wjpf-x42h-cv4m, CWE-287 / CWE-915, CVSS 3.1 8.1)"
readTime: "5 min read"
related: ["051", "073", "146"]
---

## Summary

LibreChat's local registration handler validated the request body against a schema, discarded the parsed result, and wrote fields from the raw body, including `provider`. Its social-login strategy, on failing to find a user by OAuth subject ID, fell back to an email lookup and accepted the match if the stored `provider` string equalled the inbound provider name. An unauthenticated attacker could therefore pre-register a victim's email with `provider: "google"` and a password of their choosing; when the victim later signed in with Google, LibreChat logged them into the attacker's record. Version 0.8.6 fixes the registration path.

## What was observed

GitHub advisory GHSA-wjpf-x42h-cv4m, published 17 Nov 2026 and credited to sai-sh, traced the defect through two components. On the registration side, `validateRegistration.js` checked only `ALLOW_REGISTRATION` and invite state and did not strip body fields. `AuthController.js` passed `req.body` to `registerUser`, and `AuthService.js` called `registerSchema.safeParse(user)` but then destructured `provider` from the unparsed `user` object and stored `provider ?? 'local'`. The zod schema had no `provider` field, so using its output would have dropped the value; the advisory notes that the protection never ran.

On the login side, `socialLogin.js` looked up the inbound identity by `googleId` (or the equivalent subject field for other providers). On a miss it looked the user up by email and proceeded when `existingUser?.provider === provider`. The comparison was on the provider's name, not on the subject identifier the provider had just asserted. `handleExistingUser` in `process.js` then updated avatar and email but never wrote the subject ID, so the record stayed unbound and the same fallback ran on every later login.

```
# 1. unauthenticated, before the victim has an account
POST /api/auth/register  { email: "victim@corp.example", password: "<attacker>", provider: "google", ... }
#    -> stored as { email: victim, provider: "google", googleId: null, password: <attacker hash> }
# 2. victim signs in with Google
#    googleId lookup misses -> email lookup hits -> provider "google" == "google" -> session issued
# 3. attacker logs in locally with the same password -> same user record
```

The local password strategy did not restrict by provider, so the attacker retained password login to the record the victim was now using. Everything the victim created after that point (conversations, uploaded files, stored API keys, agents, memories, presets) was readable and writable from the attacker's session. The social-registration gate `ALLOW_SOCIAL_REGISTRATION` did not help, because the existing-user branch was evaluated before it. If the planted record was the first registration on a fresh deployment, it was also promoted to administrator. With `ALLOW_UNVERIFIED_EMAIL_LOGIN=true` the record was usable immediately; with email verification on, the advisory states the record was still created.

The advisory describes the issue as a bypass of an earlier fix, PR #8999, and as distinct from issue #8980, which required an attacker-controlled identity-provider account. Here a single unauthenticated POST was sufficient. The maintainer's audit note confirmed the fix by source review rather than by re-running the exploit, and recorded that a separate report about unverified provider-email trust remained open.

The rating is high. `ALLOW_REGISTRATION=true` is the value in the shipped `.env.example`, social login is a routine addition to multi-user deployments, and the exposed data is another user's private chat history, files and credentials. The attack required a known or guessable victim email and that the victim had not yet signed in.

## Mitigation

Upgrade LibreChat to 0.8.6 or later, which persists only schema-validated profile fields at registration. On affected versions, set `ALLOW_REGISTRATION=false` where social login is the intended sign-in path. Operators should audit user records whose `provider` is not `local` but which carry a password hash and no provider subject ID; such records indicate a planted account, and any that a real user has since signed into should have their password cleared, sessions revoked and stored API keys rotated.

An identity link keyed on email and a provider name is not an identity link. Account matching after an OAuth callback has to compare the subject the provider asserted, or it trusts whoever wrote the row first.
