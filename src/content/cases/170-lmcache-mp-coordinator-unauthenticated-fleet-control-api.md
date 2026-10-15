---
caseId: "170"
title: "LMCache's multiprocess coordinator bound its fleet control API to all interfaces with no authentication on any route"
filed: "2026-10-15"
filedDisplay: "15 Oct 2026"
firstObserved: "07 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "LMCache multiprocess coordinator (through 0.5.5; no fixed release identified at disclosure)"
cve: "CVE-2026-107205 (GitHub issue #5508; VulnCheck advisory; CWE-306)"
readTime: "3 min read"
related: ["163", "037", "132"]
---

## Summary

The LMCache multiprocess coordinator, which tracks cache instances, quotas and key placement across a serving fleet, started an HTTP control API on `0.0.0.0:9300` with no authentication. Any host that could reach the port could register or remove instances, rewrite quotas, inject events and enumerate cache keys. No fixed release was identified at disclosure.

## What was observed

The coordinator's configuration hardcoded `host: "0.0.0.0"` and `port: 9300`. Its FastAPI application mounted routers without authentication middleware, and the reporter's scan of the source found no API-key, token or auth handling. The reporter also noted that the companion controller API server defaulted to `0.0.0.0:9000` with the same absence of authentication.

The reported coordinator routes were `POST /instances` with heartbeat and `DELETE` variants, `PUT /quota/config` and `PUT /quota/{cache_salt}`, `POST` and `DELETE /cache/pins`, `POST /events`, and the directory routes `GET /directory/keys`, `POST /directory/lookup` and `POST /directory/blend-lookup`. Deleting an instance removed its placements from scheduling. Quota writes changed per-tenant limits keyed by `cache_salt`. The directory routes disclosed which cached prefixes existed and where they were placed.

```
# any client on the network, no credentials
# POST /instances            -> register a fake cache instance
# DELETE /instances/{id}     -> drop a real instance from scheduling
# PUT /quota/{cache_salt}    -> overwrite a tenant's quota
# GET /directory/keys        -> list cached keys and placements
```

The reporter's calls succeeded without credentials in each of these cases. The reporter stated that no patched version existed. The issue was open without maintainer comments when reviewed. VulnCheck lists CWE-306; the advisory scores the flaw CVSS 8.8 (v3.1 vector as proposed by the reporter) and 8.6 in the CVE record's summary. RagBleed rates the mechanism medium: the coordinator exists only in multiprocess deployments, and the verified impact is availability loss, quota tampering and placement metadata disclosure, not exposure of cached content itself. The registration and event routes could also support the cache-poisoning scenarios the CVE record mentions, but the reporting does not describe a verified poisoning path, and this entry does not claim one.

## Mitigation

No patched version was identified in the sources; check the LMCache releases before relying on any version. Until a fix ships, bind the coordinator and controller API to loopback or a private interface and restrict ports 9300 and 9000 with host firewalls or network ACLs. Review access logs for unexpected requests to the routes above. Cluster coordination planes inherit the trust assumptions of the network they are placed on, and a default bind to every interface turns that assumption into an exposure.
