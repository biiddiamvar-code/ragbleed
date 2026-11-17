---
caseId: "210"
title: "AWS Timestream for InfluxDB MCP Server resolved each connection field independently, sending the server's InfluxDB token to any URL the model supplied"
filed: "2026-11-17"
filedDisplay: "17 Nov 2026"
firstObserved: "16 Nov 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "awslabs.timestream-for-influxdb-mcp-server (pip, >=0.0.12, <0.0.19; fixed in 0.0.19), InfluxDB data-plane tools (InfluxDBQuery, InfluxDBWritePoints, InfluxDBWriteLP, InfluxDBListBuckets, InfluxDBCreateBucket, InfluxDBListOrgs, InfluxDBCreateOrg)"
cve: "CVE-2026-126681 (GHSA-2f9r-g4f3-wc2j, CWE-923, CVSS 3.1 5.5; AWS Security Bulletin 2026-185-AWS)"
readTime: "4 min read"
related: ["209", "193", "186"]
---

## Summary

The InfluxDB tools in the AWS Timestream for InfluxDB MCP Server accepted an optional `url`, `token` and `org` from the caller and fell back to the server's environment variables one field at a time. A tool call that carried only a `url` was sent to that URL with the operator's `INFLUXDB_TOKEN` attached. Content that steered the model into supplying an attacker-controlled URL was sufficient to exfiltrate the token. Version 0.0.19 stops mixing caller-supplied and server-held values and requires any caller URL to be on an operator allowlist.

## What was observed

AWS published GHSA-2f9r-g4f3-wc2j and Security Bulletin 2026-185-AWS on 16 Nov 2026, crediting @Yuremin, @FORIMOC and @invoke1442. The advisory describes improper restriction of the endpoints the server connects to and names prompt injection into the MCP client context as the delivery path. It does not name the parameter involved. The mechanism below was confirmed by diffing the 0.0.18 and 0.0.19 packages on PyPI.

In 0.0.18, every InfluxDB data-plane tool exposed an optional `url` field documented as falling back to `INFLUXDB_URL`, with matching optional `token` and `org` fields. A shared resolver combined them per field:

```
# 0.0.18 resolver (abridged)
resolved_url   = url   or INFLUXDB_URL     # caller value wins
resolved_token = token or INFLUXDB_TOKEN   # server secret fills the gap
resolved_org   = org   or INFLUXDB_ORG
# only check on the URL: scheme must be http or https
```

The InfluxDB client then authenticated to `resolved_url` with `resolved_token`. A call to `InfluxDBQuery` or `InfluxDBListBuckets` with a foreign host in `url` and no `token` delivered the server's token to that host in the request's authorization header. No host restriction existed beyond the HTTP(S) scheme check. The override was a documented tool argument present by default; no configuration change was needed to expose it.

The attacker did not need access to the MCP server. Text placed anywhere the agent read, such as a document, ticket or web page, that persuaded the model to "query the metrics at" an attacker URL was enough. The token carried whatever InfluxDB rights the operator had granted it.

Severity is rated high, above the medium CVSS 3.1 score of 5.5. The vector scores the attack as local with user interaction, but the override was on by default, the trigger was ordinary indirect prompt injection, and the exposed value was a standing database credential.

## Mitigation

Upgrade to `awslabs.timestream-for-influxdb-mcp-server` 0.0.19 or later and rotate any InfluxDB API token that was configured on an affected version, as the advisory directs. In 0.0.19, a caller supplying any connection field must supply all of them, server values are never substituted in, and a caller URL must match `INFLUXDB_URL` or an entry in the new `INFLUXDB_ALLOWED_URLS` variable after normalization; URLs with embedded credentials, query strings or fragments are rejected. Until upgrading, AWS recommends a least-privilege token and keeping the server away from clients that process untrusted content.

A credential fallback that operates per field turns every optional destination parameter into an exfiltration channel. Where a tool lets the model choose the endpoint, the server's own secret must never be the default that fills in the rest.
