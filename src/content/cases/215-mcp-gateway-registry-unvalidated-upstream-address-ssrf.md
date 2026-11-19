---
caseId: "215"
title: "mcp-gateway-registry accepted unvalidated upstream addresses on server registration and update, letting registrants proxy requests to internal services and instance metadata"
filed: "2026-11-19"
filedDisplay: "19 Nov 2026"
firstObserved: "11 Nov 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp-gateway-registry (agentic-community/mcp-gateway-registry, 1.0.3 through 1.34.0; fixed in 1.35.0)"
cve: "CVE-2026-125926 (GHSA-fc39-fwh3-wv5r, CWE-918, CVSS 3.1 8.5 / CVSS 4.0 6.3; AWS Security Bulletin 2026-180-AWS)"
readTime: "3 min read"
related: ["070", "212", "157"]
---

## Summary

mcp-gateway-registry, an open-source registry and proxy that handles discovery, access control and forwarding for Model Context Protocol servers, did not validate the upstream address supplied when a server was registered or modified. A user holding register or modify permission could point a server entry at a host on the deployment's internal network, and the gateway would send requests there on that user's behalf, in some cases returning the responses. Version 1.35.0 validates upstream addresses at registration and modification time.

## What was observed

AWS published Security Bulletin 2026-180-AWS and the project published GHSA-fc39-fwh3-wv5r on 11 Nov 2026, with CVE-2026-125926 issued the same day. The researcher "novice-22" was credited for coordinated disclosure.

The flaw sat in the server registration and update API. A registered server's upstream address was stored and later used as the proxy target without any check on where it pointed. Because the gateway's job is to forward tool traffic to that address, a registrant could turn it into a request relay: an entry aimed at an internal service or a cloud instance metadata endpoint caused the gateway itself to make the request from inside the network boundary, and some responses came back to the caller. The advisory names the cloud instance metadata service, and the temporary role credentials it issues, as a reachable target depending on network configuration.

```
# authenticated user with register/modify permission (illustrative)
register or update server:
    upstream = "http://<internal service or metadata address>/..."   # not validated
# client -> gateway -> upstream   # gateway issues the request from inside the network
#                                 # response returned to the user in some cases
```

The published advisory and release notes do not describe the specific validation logic added in 1.35.0 (blocked ranges, DNS resolution handling); this case does not characterise it further. AWS notes that a separate management-API issue fixed in 1.25.0 does not cover this one: deployments on 1.25.0 through 1.34.0 remain exposed.

Severity is rated medium, below the CVSS 3.1 score of 8.5. Exploitation required an authenticated account with permission to register or modify servers, which is a privileged role in most deployments. The reachable data was sensitive, and on EC2 with IMDSv1 and an attached role it could include credentials, which keeps the rating above low.

## Mitigation

Upgrade to mcp-gateway-registry 1.35.0 or later, and patch any fork or derivative. The upgrade does not rewrite stored configuration: review every registered server's upstream address and remove unintended entries, review logs from the affected period for unexpected registrations or changes, and if the registry carries a cloud role and activity cannot be ruled out, review that role's usage and rotate its credentials. Until upgraded, restrict register and modify permissions to trusted accounts, limit outbound traffic from the registry and auth-server components to required destinations, require IMDSv2, and scope each component's role to what it needs.

A gateway that forwards to whatever address a registrant names is an SSRF primitive by design; the destination check belongs at the point where the address is accepted, not left to the network.
