---
caseId: "060"
title: "Open WebUI's rebuilt SSRF guard still missed IPv4 addresses hidden inside NAT64 IPv6 prefixes"
filed: "2026-08-10"
filedDisplay: "10 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.9.0, <0.11.0)"
cve: "CVE-2026-70485"
readTime: "4 min read"
related: ["030", "036", "027"]
---

## Summary

Open WebUI's July 2026 fix for its SSRF guard (case 030) replaced a broken third-party validator with Python's own `ipaddress` module and closed the IPv4-mapped-IPv6 bypass. It did not account for NAT64, a standard IPv6-to-IPv4 translation mechanism that lets IPv6-only networks reach IPv4 destinations by encoding the target's IPv4 address inside a well-known IPv6 prefix. On any deployment sitting behind a NAT64 gateway, an authenticated user could wrap cloud metadata or internal service addresses in that prefix, and the fixed guard checked only the literal IPv6 address's own routability — never decoding and re-checking the IPv4 address folded inside it. Open WebUI shipped a fix in 0.11.0.

## What was observed

Open WebUI's `validate_url()` decides whether a server-side fetch (RAG URL ingestion, URL-to-markdown conversion, web-search retrieval) is allowed to proceed by calling `ipaddress.is_global` against the destination's literal IPv6 form. NAT64 (RFC 6052) is a standard mechanism, deployed on IPv6-only cloud subnets, Kubernetes clusters, and some mobile carrier networks, that embeds a destination IPv4 address in the low 32 bits of an address under the well-known prefix `64:ff9b::/96`. A gateway on that network transparently translates traffic to the encoded IPv4 destination.

```
# is_global() sees an ordinary, routable-looking IPv6 address —
# it never unpacks the IPv4 address NAT64 has folded into it
target = "64:ff9b::a9fe:a9fe"   # decodes to 169.254.169.254
ipaddress.ip_address(target).is_global  # True — passes the filter
```

Because the check operated purely on the outer IPv6 representation, an address that decoded to `169.254.169.254` (cloud instance metadata) or an RFC 1918 range passed the filter cleanly on any network where a NAT64 gateway existed to perform that translation. The request then went out from the Open WebUI server, and the response came back through the same API that returns normal RAG or web-search content.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which unpacks NAT64-encoded addresses before applying the routability check. Where upgrading isn't immediate, block outbound traffic to the NAT64 well-known prefixes `64:ff9b::/96` and `64:ff9b:1::/48` at the network layer, or route Open WebUI's egress through a forward proxy with its own hostname allow-list rather than relying on address-level filtering alone. We rate this medium rather than matching the advisory's CVSS 7.1 HIGH: unlike the IPv4-mapped-IPv6 bypass in case 030, which worked against any deployment regardless of network topology, this variant only fires where a NAT64 gateway is actually present to perform the translation — common on IPv6-only cloud and carrier networks, but not a universal default. The recurring lesson holds regardless: an IP-filtering SSRF guard has to canonicalize every encoding a network might resolve, not just the address literal it was handed.
