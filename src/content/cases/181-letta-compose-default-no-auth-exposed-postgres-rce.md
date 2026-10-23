---
caseId: "181"
title: "Letta's shipped compose.yaml left the API password middleware disabled and exposed PostgreSQL with default superuser credentials"
filed: "2026-10-23"
filedDisplay: "23 Oct 2026"
firstObserved: "20 Oct 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Letta (letta-ai/letta, through 0.16.8)"
cve: "CVE-2026-77936 (CWE-1188, CVSS 4.0 9.3; CNA VulnCheck)"
readTime: "3 min read"
related: ["177", "047", "144"]
---

## Summary

Letta, an open-source stateful agent server, shipped a `compose.yaml` that did not set `LETTA_SERVER_SECURE`. The password middleware was therefore never added to the REST application, and every API route accepted unauthenticated requests. The same file published a PostgreSQL port carrying default superuser credentials. The CVE record lists versions through 0.16.8 as affected and names no patched release.

## What was observed

The CVE was published on 20 Oct 2026 and modified on 21 Oct 2026. Per the record, the authentication middleware is conditional: when the secure flag is absent, the server registers no credential check at all. The reference deployment file left the flag unset, so a default `docker compose up` produced an instance with open routes. Secondary reporting lists two reachable paths: `POST /v1/tools/run`, which executes caller-supplied Python, and the `/v1/admin` routes, which manage users. The second path bypasses the API entirely. The database port was bound to external interfaces with a superuser account, and PostgreSQL's `COPY ... PROGRAM` statement runs a command as the database server's OS user.

```
# Illustrative
# compose.yaml: LETTA_SERVER_SECURE not set  -> no password middleware
# POST /v1/tools/run  (no Authorization header) -> Python executed on server
# psql to exposed port, default superuser     -> COPY ... PROGRAM -> OS command
```

Agent servers of this kind store conversation memory and tool credentials, so code execution on the host also exposes the retrieval and memory contents the agents hold. The record carries no researcher credit and describes no in-the-wild exploitation. A secondary summary reported no public proof of concept and no CISA KEV listing at the time of writing; the CVSS figure there (9.8) differs from the CVE record (9.3 under CVSS 4.0), and the record is used here.

Rubric rating is high: the vulnerable state is the default shipped deployment, and the result is unauthenticated code execution with access to stored agent data.

## Mitigation

No fixed version is identified in the sources reviewed. Set `LETTA_SERVER_SECURE` explicitly and supply a strong server password, replace the default PostgreSQL credentials, and remove the database port mapping or restrict it to the application network. Place the server behind an authenticating reverse proxy and block unauthenticated access to `/v1/tools/run` and `/v1/admin`. Review web logs for requests to those routes without credentials and database logs for `COPY ... PROGRAM` statements. Monitor the upstream repository for a release that makes authentication the default.

A reference compose file is the deployment most users run. When it ships with authentication off, the secure setting is a property of the example, not of the user's decision.
