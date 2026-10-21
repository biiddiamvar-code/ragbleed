---
caseId: "177"
title: "Langflow's webhook endpoint skipped API key validation under a default-false setting and ran flows as their owner for any caller holding the flow UUID"
filed: "2026-10-21"
filedDisplay: "21 Oct 2026"
firstObserved: "12 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Langflow (pip package langflow, >=1.7.0, <=1.9.0; patched in 1.9.1)"
cve: "CVE-2026-8505 (GHSA-cf6m-vc3m-7cgm, CWE-306, CVSS 3.1 9.8)"
readTime: "3 min read"
related: ["155", "052", "173"]
---

## Summary

Langflow's webhook route called an authentication helper that returned the flow owner without checking the request's API key whenever `WEBHOOK_AUTH_ENABLE` was `False`. The setting defaulted to `False` in versions 1.7.0 through 1.9.0, so webhook endpoints were public on a stock install. Release 1.9.1 changed the default to `True`.

## What was observed

The GitHub advisory was published on 12 Aug 2026 and added to the GitHub Advisory Database on 5 Oct 2026. The flaw sat in `AuthService.get_webhook_user`. With the setting disabled, the function resolved the flow's owner and returned it as the authenticated user, with no comparison against a supplied key. Authorization for the webhook therefore rested on one fact: whether the caller knew the flow's UUID. The advisory describes this as reliance on security by obscurity.

```
# Illustrative
# POST to the webhook route of a flow, identified only by its UUID
#   - no API key header
# WEBHOOK_AUTH_ENABLE == False (default in 1.7.0-1.9.0)
# get_webhook_user() returns flow owner -> flow executes with owner's identity
```

The advisory lists three consequences: code execution through flow components that run Python, denial of service through concurrent heavy flows, and unauthorized changes to databases or external systems reachable by the flow's credentials. Exploitation status and the discovery path were not stated in the advisory. This case differs from case 155, which concerned a public-flow build endpoint that accepted caller-supplied graph data; here the flow definition was not altered, and the exposure came from the default authentication setting alone.

Rubric rating is high. The vulnerable behavior was the default configuration, and a flow runs with its owner's stored credentials and component code. The UUID requirement limits discovery but is not an access control.

## Mitigation

Upgrade to Langflow 1.9.1 or later. The fix, pull request 12845, makes webhook authentication enabled by default. On affected versions, set `LANGFLOW_WEBHOOK_AUTH_ENABLE=true` explicitly, and do not set it to `false` after upgrading. Treat flow UUIDs as identifiers, not secrets, and rotate credentials stored in flows that had webhooks reachable from untrusted networks. A security control that ships disabled behaves like a missing one for most deployments.
