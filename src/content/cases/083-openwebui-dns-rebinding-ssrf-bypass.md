---
caseId: "083"
title: "Open WebUI's SSRF guard checked a DNS answer once and trusted the HTTP client to get the same one twice"
filed: "2026-08-24"
filedDisplay: "24 Aug 2026"
firstObserved: "04 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, < 0.11.0)"
cve: "CVE-2026-54020 (GHSA-h6x2-583h-x99r)"
readTime: "4 min read"
related: ["030", "060", "062"]
---

## Summary

Every user-reachable fetch in Open WebUI — RAG URL ingestion, web-search retrieval, URL-to-markdown conversion — is meant to be gated by a check that resolves the target hostname and rejects private, loopback, and link-local addresses before the request goes out. That check resolved the hostname once, validated the address it got back, and then let the underlying HTTP client resolve the same hostname again when it actually opened the connection. An attacker who controls the authoritative DNS for a domain they submit can answer the first lookup with a public address and the second with an internal one, so the fetch lands somewhere the check was specifically built to block. Fixed in Open WebUI 0.11.0 as CVE-2026-54020.

## What was observed

This is a time-of-check-to-time-of-use race, CWE-367, layered under the SSRF weakness it defeats, CWE-918. Open WebUI's guard function did the validation work correctly for the address it saw: it resolved the submitted hostname, checked the resolved IP against the private/loopback/link-local blocklist, and rejected anything on it. Where the design broke down was the gap between that check and the actual network call. The guard validated an IP address; the HTTP client, moments later, was handed the original hostname and resolved it independently, trusting whatever answer the DNS server gave at that moment.

```
# illustrative: validation and connection resolve the hostname separately
ip = resolve(hostname)          # attacker's DNS answers a public address here
if is_private_or_internal(ip):
    reject()
# ... time passes ...
response = http_client.get(hostname)   # resolves again — attacker's DNS answers 127.0.0.1 or 169.254.169.254 here
```

Nothing about this required a misconfigured network or a special deployment topology — the only infrastructure an attacker needs is a domain name with authoritative DNS they control, which costs nothing beyond registering a domain. Because the guard was the single enforcement point for every server-side fetch across RAG ingestion, web search, and markdown conversion, and because most of those code paths return the fetched content back to the requesting user, a successful bypass reached internal services and cloud instance metadata and handed the response straight back through the normal chat interface. This is the third distinct way Open WebUI's SSRF guard has been shown to miss an address it was built to catch, following the broken IPv6 validator call (case 030) and the NAT64-encoded bypass (case 060) — three different technical roots, but the same guard, the same class of consequence, and the same fix release.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later. The fix pins the connection to the address that was actually validated rather than letting the HTTP client re-resolve the hostname, closing the gap between check and use. Where upgrading isn't immediate, route Open WebUI's outbound fetches through a forward proxy that resolves once and connects to that resolved address itself, and block egress to `169.254.169.254` and RFC 1918 ranges at the network layer as a backstop independent of any application-level check. We rate this high rather than matching the advisory's CVSS 6.3 MEDIUM: the rubric this site applies weighs how reachable the mechanism is, and DNS rebinding here requires nothing an attacker doesn't already control by default — no special network position, no rare deployment condition, just a domain — while a successful hit reaches cloud credentials or internal infrastructure through a widely deployed default configuration. Any SSRF defense that validates an address and then re-resolves the same hostname later is not actually validating what it connects to — it's validating a moment in time that the attacker gets to choose not to repeat.
