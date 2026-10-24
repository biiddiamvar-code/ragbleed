---
caseId: "183"
title: "LiteLLM used one AES-GCM key for stored secrets and bearer session tokens, letting an internal user forge a proxy_admin token through an encryption oracle"
filed: "2026-10-24"
filedDisplay: "24 Oct 2026"
firstObserved: "22 Oct 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "litellm (BerriAI; >=1.87.0 <1.100.4, >=1.101.0 <1.101.3, >=1.102.0 <1.102.2, >=1.103.0 <1.103.1, 1.104.0-rc.1; default-config exposure from 1.91.0)"
cve: "CVE-2026-114612 (GHSA-7hp6-4w63-5g45, CWE-269/CWE-345/CWE-441, CVSS 3.1 9.9)"
readTime: "4 min read"
related: ["102", "158", "057"]
---

## Summary

The LiteLLM proxy encrypted at-rest secrets and UI/CLI session tokens with the same key and no purpose binding. An authenticated internal user could store attacker-chosen JSON through an endpoint that encrypts it, read the ciphertext back, and replay it as a bearer token carrying an administrator role. The CVE record states that administrative access then extends to arbitrary command execution through the MCP stdio endpoint. Fixed releases separate the two uses with a purpose-bound authenticated-data tag.

## What was observed

The CVE record was published on 22 Oct 2026. The record describes one cryptographic context reused for at-rest secrets and session tokens. A technical write-up of the issue (cvereports, a secondary source; the fix commit and advisory were not independently reviewed in this run) gives the mechanism as follows. A single AES-256-GCM key is derived from the configured salt key (falling back to the master key). The GCM calls carry no associated data, so nothing ties a ciphertext to its purpose; the only purpose marker is a text prefix outside the authenticated boundary, which can be removed. The session-token validator decrypts any bearer value that is valid ciphertext under the key and trusts a `user_role` field in the plaintext.

Any endpoint that encrypts a user-supplied string and returns it therefore acts as an encryption oracle. The write-up names key generation with per-key logging-callback metadata as that path: a callback secret field is stored encrypted and is readable through key info. An `internal_user` credential is sufficient to reach it.

```
# Illustrative, no payload
# 1. internal_user stores attacker-shaped JSON in an encrypted metadata field
# 2. the stored ciphertext is read back and its storage prefix removed
# 3. the remainder is sent as a bearer token to an admin route
# 4. validator decrypts it, trusts the embedded role, grants proxy_admin
```

Exposure depends on version. Per the CVE record, releases 1.87.0 through 1.90.x are exploitable only with `EXPERIMENTAL_UI_LOGIN` enabled, and releases after 1.91.0 are exploitable in the default configuration. The write-up's dates are internally inconsistent (it places the fix and advisory on 29 Sep 2026, while the CVE and NVD records date from 22 Oct), so the first-disclosure date is recorded here as the CVE publication date.

Rubric rating is high, in line with the 9.9 base score: default configuration on current branches, a low-privilege starting role, and a result that exposes every tenant's keys and the host.

## Mitigation

Upgrade to 1.100.4, 1.101.3, 1.102.2, 1.103.1, or 1.104.0-rc.2, matching the branch in use. Per the write-up, the fix gives bearer tokens their own encrypt and decrypt functions with a fixed prefix used as GCM associated data, so tokens minted under the old scheme stop validating and replayed storage ciphertexts fail the tag check. Sessions are expected to require re-login after the upgrade. On 1.87.0 to 1.90.x, leave `EXPERIMENTAL_UI_LOGIN` unset. Where an upgrade is delayed, restrict who holds internal-user keys and rotate the salt key after patching, since forged tokens may have been issued. Disable MCP stdio registration if it is unused.

One key serving two purposes is an authentication boundary that exists only by convention: ciphertext needs a domain tag inside the authenticated data, not beside it.
