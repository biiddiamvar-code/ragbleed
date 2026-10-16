---
caseId: "171"
title: "Ollama's pull path followed registry redirects without re-validating the destination, and the CVE record names a different function than the fix"
filed: "2026-10-16"
filedDisplay: "16 Oct 2026"
firstObserved: "12 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Ollama (<= 0.34.1; fixed in 0.34.2)"
cve: "CVE-2026-108836 (GHSA-fr42-jr2w-mx59, CWE-918; CNA: VulDB)"
readTime: "4 min read"
related: ["162", "083", "020"]
---

## Summary

CVE-2026-108836 describes a server-side request forgery in the Ollama Pull API, affecting versions up to and including 0.34.1 and fixed in 0.34.2. The CVE record attributes the flaw to the `IsValid` function in `types/model/name.go`, but the referenced fix commit does not modify that file. The root cause could not be independently verified from the sources available, and this entry separates what is documented from what is inferred.

## What was observed

The CVE record states that manipulation of `IsValid` in the Pull API component leads to SSRF, exploitable remotely without authentication, with a public exploit disclosed. The GitHub advisory lists the affected and patched version fields as unknown; the description points to 0.34.2 and commit `dfabde4`. VulDB scored the issue CVSS 4.0 5.5 and CVSS 3.1 7.3. No credited reporter is listed, and no in-the-wild exploitation was reported at the time of review.

The referenced commit (PR #18512) changes redirect handling in `server/images.go` and the transfer package. Before following a redirect, the server now checks the target's scheme and the addresses it resolves to, repeats the DNS check on every hop instead of trusting the first lookup, and refuses redirects that downgrade an HTTPS session to plain HTTP. The `--insecure` option still relaxes address checks so private registries remain reachable, but it does not relax the scheme check. The PR description does not use the term SSRF or state a motivation.

```
# Inferred, not tested or confirmed by the vendor:
# pull request names a registry the caller controls
# registry answers a blob request with a redirect
# redirect target is an internal or metadata address
# pre-fix code followed it without re-checking the resolved address
```

That chain is an inference from the shape of the fix. The CVE record's function name and the commit's contents do not match, so whether they describe one flaw or two is undocumented. Ollama had no published vendor advisory in the sources reviewed.

RagBleed rates the mechanism medium: the pull endpoint is reachable on any Ollama instance exposed beyond loopback, but the verified fix scope is redirect validation and the available scoring reports only low confidentiality, integrity and availability impact.

## Mitigation

Upgrade to a current release. Version 0.34.2 contains the fix, but 0.34.2 up to 0.35.0 is separately affected by a path traversal (CVE-2026-103663), so 0.35.0 or later is the safer floor. Do not expose port 11434 to untrusted networks, place any non-loopback instance behind an authenticating proxy, and block egress from the Ollama host to link-local and private ranges. When a CVE record and its fix disagree about location, treat the fix as the ground truth for what changed and the record as unverified for why.
