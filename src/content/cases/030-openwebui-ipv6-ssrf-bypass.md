---
caseId: "030"
title: "Open WebUI's SSRF guard silently failed on IPv6, letting web search fetch cloud metadata"
filed: "2026-07-26"
filedDisplay: "26 Jul 2026"
firstObserved: "09 May 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, <=0.8.12; patched >=0.9.0)"
cve: "No CVE assigned; disclosed via GHSA-4v7r-f4w8-8972"
readTime: "5 min read"
related: ["011", "015", "027"]
---

## Summary

Open WebUI's RAG web-search feature converts a user- or model-supplied URL into page content before handing it to the model, and every endpoint that performs that fetch routed the target address through one guard function, `validate_url()`. That guard called a third-party library's IPv6 validator with a keyword argument the library never implemented, so the call silently returned an object that behaved as `False` in the surrounding check — meaning no IPv6 address, private or otherwise, was ever rejected. Combined with an unhandled IPv4-mapped-IPv6 form and several unblocked reserved IPv4 ranges, an authenticated user could route a request through the Open WebUI server to cloud instance metadata, localhost-bound services, or internal infrastructure.

## What was observed

`validate_url()` was Open WebUI's single point of enforcement for outbound URL fetches, called from `/api/v1/retrieval/process/web`, `/api/v1/images/edit`, and other endpoints where a user or the model itself supplies a target URL. Its intended behavior was to reject any address resolving to a private, loopback, or link-local range. For IPv6 addresses, the function called `validators.ipv6(ip, private=True)` — but the `validators` library's `ipv6()` function does not accept a `private` keyword, and passing one caused the call to return a `ValidationError` object instead of raising or returning `False`. Because a `ValidationError` instance evaluates as falsy in a boolean context, the surrounding `if validators.ipv6(ip, private=True):` check never fired.

That flaw alone was enough, but two more gaps widened it. IPv4-mapped IPv6 addresses (`::ffff:169.254.169.254`) bypassed the IPv4-specific checks entirely, since the code treated them as IPv6 and hit the same broken condition. And several IANA-reserved IPv4 ranges — `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24` among them — were never in the blocklist to begin with. A prior advisory (CVE-2025-65958) had already attempted to close SSRF in this exact function and left all three gaps open.

```
# validators.ipv6() has no `private` parameter —
# calling it with one returns a ValidationError object, not False
if validators.ipv6(ip, private=True):   # always falsy; never raises
    reject(ip)
```

Any authenticated user could submit a web-search or image-edit request whose target was an IPv4-mapped IPv6 form of `169.254.169.254` and have the Open WebUI server fetch it on their behalf. On cloud infrastructure still serving IMDSv1, that request path leads directly to temporary IAM credentials.

## Mitigation

Upgrade to Open WebUI 0.9.0 or later, which replaces the `validators`-library calls with Python's own `ipaddress` module and checks `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, and `is_unspecified` directly, including on the unwrapped IPv4 address inside any IPv4-mapped IPv6 literal. Where upgrading isn't immediate, block outbound traffic from the Open WebUI process to `169.254.169.254` and RFC 1918 ranges at the network layer, and migrate any cloud instances still on IMDSv1 to IMDSv2, which requires a signed request token and closes the credential-theft path even if a URL-validation gap resurfaces. A security check built on a third-party library's undocumented keyword argument is a check that can silently do nothing — the only way to catch that is to test the negative case, not to trust that passing an argument named for the thing you want blocked actually blocks it.
