---
caseId: "068"
title: "Verba's WebSocket import endpoint let unauthenticated callers turn document ingestion into SSRF"
filed: "2026-08-15"
filedDisplay: "15 Aug 2026"
firstObserved: "21 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Weaviate Verba / GoldenVerba (all versions through 2.1.3; project archived, no fix planned)"
cve: "CVE-2026-65318"
readTime: "4 min read"
related: ["027", "015", "010"]
---

## Summary

Verba, the reference RAG chatbot maintained by Weaviate, exposes a WebSocket route at `/ws/import_files` that accepts document-ingestion jobs from clients. The route carries no authentication or authorization check. When a submitted job selects the HTMLReader importer, Verba's backend fetches whatever URL the client supplies and streams the response back over the same socket, giving an unauthenticated caller a direct, bidirectional SSRF primitive into the server's network position. This is a second, independent SSRF hole in the same product covered by case 027 — different endpoint, different missing control, same underlying pattern of an ingestion feature trusting caller-supplied URLs.

## What was observed

Document ingestion in RAG platforms routinely needs to fetch external content: a URL comes in, the server retrieves it, parses it, and indexes the result. Verba's HTMLReader importer implements exactly that path through `/ws/import_files`, but the WebSocket handler never checks who is connecting. No session, no API key, no prior interaction with the application — a raw WebSocket connection to the endpoint is enough to submit an import job.

```
# what a legitimate import job looks like
connect ws://verba-host/ws/import_files
send { reader: "HTMLReader", url: "https://docs.example.com/page" }

# what the endpoint also accepts, from anyone
send { reader: "HTMLReader", url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

Because the fetch routine performs no destination validation — no private-range blocking, no metadata-endpoint filtering, no allowlist — the server will retrieve whatever address it's given and hand the response back to the caller through the WebSocket stream. On cloud-hosted deployments that means direct access to instance metadata services and any IAM credentials they expose; on any deployment it means reconnaissance and request-forgery against co-located services, including the Weaviate instance Verba normally talks to.

The timing compounds the exposure. The Weaviate team archived the Verba repository on 8 June 2026, roughly six weeks before this report surfaced, so there is no maintained upstream to ship a fix. Every running instance is exposed for as long as it stays running, with no patch path.

## Mitigation

There is no fixed version to upgrade to. Treat any deployed Verba instance as permanently exposed rather than as a bug awaiting a patch: place it behind an authenticating reverse proxy so `/ws/import_files` is unreachable without credentials, or remove it from any network segment with a route to instance metadata services and co-located data stores. Where the instance must keep running, block outbound traffic to `169.254.169.254` and equivalent metadata hosts at the network layer, and on AWS enforce IMDSv2 with a hop limit of 1 so a captured SSRF primitive can't retrieve role credentials even if the request goes through. Disabling the HTMLReader importer entirely removes the vulnerable code path if URL-based ingestion isn't operationally required.

The independent CVSS scoring on this one rates confidentiality impact as low, which undersells the mechanism: an unauthenticated, URL-controlled fetch that reaches cloud metadata endpoints is a credential-theft primitive, not a low-severity information leak, and this entry rates it accordingly. The broader pattern, again: any ingestion feature that fetches a caller-supplied URL is an SSRF primitive by default, and needs destination validation as a first-class control, not an afterthought bolted onto one of several entry points while the others stay open.
