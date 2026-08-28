---
caseId: "088"
title: "MLflow validated a webhook URL once and then followed it wherever it redirected"
filed: "2026-08-28"
filedDisplay: "28 Aug 2026"
firstObserved: "17 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "MLflow Tracking Server, model-registry webhook delivery (versions before 3.15.0)"
cve: "CVE-2026-64849 (GHSA-7gwp-5pfp-969j); added to CISA KEV catalog 19 Aug 2026"
readTime: "5 min read"
related: ["036", "015", "070"]
---

## Summary

MLflow's Tracking Server lets any user who can reach it register webhooks that fire on model-registry events, such as a new model version being logged, and POST the event payload to a destination URL. To stop that feature from being turned into an internal network prober, MLflow checked the destination at registration time and rejected anything that didn't resolve to a public IP address. The check ran exactly once. When the webhook was later triggered — or tested, via an endpoint that echoes the full response back to the caller — MLflow's HTTP client followed any redirect the destination returned without checking where it led. A registered URL that answered with a 302 to `169.254.169.254`, the cloud metadata address every major provider uses to hand instance credentials to anything that asks, passed the one-time check and then delivered the redirect target's response straight back to an unauthenticated caller. Scanning for exposed MLflow instances began within hours of the CVE's assignment on August 17, 2026, and CISA added it to its Known Exploited Vulnerabilities catalog two days later.

## What was observed

The root cause was a time-of-check to time-of-use gap between two functions handling the same URL. `_validate_webhook_url` ran at webhook creation and confirmed the hostname resolved to a public, non-internal address — a reasonable control against SSRF, evaluated at the only moment MLflow actually looked at where the traffic would go. `_send_webhook_request`, invoked both when a webhook fires for real and when an operator clicks "test" in the UI, used the `requests` library with its default behavior of transparently following HTTP redirects, and never repeated the validation against the address a redirect actually pointed to:

```
# _validate_webhook_url(url) — runs once, at registration
# _send_webhook_request(url) — runs later, follows 3xx redirects silently
# neither call re-validates the post-redirect destination
```

An attacker with permission to register a webhook — or, on the `/test` code path, no authentication at all on a default server — pointed it at a URL under their control that resolved publicly and passed the initial check, then had that URL respond with a redirect to `127.0.0.1` or the cloud metadata service. MLflow's webhook delivery followed the redirect and, because the test endpoint reflects the response body, handed the internal service's answer directly back to the caller: IAM role credentials, instance metadata, anything reachable on the loopback interface. Security firm watchTowr reported observing indiscriminate scanning for exposed MLflow deployments beginning within hours of the CVE being assigned, describing the technique as proxying requests through the tracking server to interact with internal services from outside. The same TOCTOU gap is also reachable through DNS rebinding rather than an HTTP redirect: a hostname that resolves to a public address at registration time and to an internal one at request time defeats the validation just as completely, since nothing re-resolves or re-checks the address once the redirect (or rebind) has happened.

> A validation that runs once and a delivery path that runs later are, for SSRF purposes, two different security boundaries pretending to be one.

## Mitigation

Upgrade MLflow to 3.15.0 or later, which closes the redirect-following gap. Any organization running an internet-reachable MLflow Tracking Server before patching should treat this as a likely-exploited incident rather than a theoretical one: review access logs for outbound requests to `169.254.169.254` or loopback addresses around webhook test or delivery events, and rotate any cloud credentials the MLflow host's role could reach. Longer term, validate-then-use patterns for any outbound URL an application controls need the check repeated at the point of use, not just at the point of configuration — a redirect, a TTL expiry, or a DNS rebind can silently invalidate an earlier check, and an HTTP client that follows redirects by default will walk straight through a validation boundary that assumed it wouldn't.
