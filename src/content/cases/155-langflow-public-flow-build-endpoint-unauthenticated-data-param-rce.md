---
caseId: "155"
title: "Langflow's unauthenticated public-flow build endpoint accepted caller-supplied flow data and executed its node code"
filed: "2026-10-08"
filedDisplay: "08 Oct 2026"
firstObserved: "16 Mar 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Langflow (pip package langflow, <= 1.8.2; patched in 1.9.0), build_public_tmp public-flow endpoint"
cve: "CVE-2026-33017 (GHSA-vwmf-pq79-vjvx, CVSS v4 9.3)"
readTime: "3 min read"
related: ["040", "052", "045"]
---

## Summary

Langflow's endpoint for building public flows required no authentication and accepted an optional `data` parameter. When the parameter was present, the server built the graph from the caller's data instead of the stored flow. Node definitions in that data could contain Python source, which reached an unsandboxed `exec()` call during graph construction. The result was unauthenticated remote code execution at the privileges of the Langflow server process.

## What was observed

The advisory was published on 16 Mar 2026. The reporter tested against Langflow 1.7.3 and obtained code execution in every run.

The endpoint, `build_public_tmp`, exists so that flows marked public can be run by anonymous visitors. That design makes the missing authentication intentional, which is why the fix for the earlier CVE-2025-3248, which added authentication to a different endpoint, did not apply here. The flaw was the optional `data` parameter: a public flow was meant to execute only its stored definition, but the endpoint let the request body replace that definition.

```
# Illustrative
# POST to the public-flow build endpoint for a known public flow UUID
#   - arbitrary client_id cookie value
#   - body: "data" = flow graph whose component code field holds attacker Python
# server builds the graph from "data" -> exec() on the component code
```

The prerequisites were a public flow and knowledge of its UUID. Under the default `AUTO_LOGIN=true` setting an attacker could create the public flow themselves, which removed the dependency on an existing one. The advisory lists full server-process privileges as the impact: file read and write, command execution, environment variables and stored credentials, and the flows and messages held by the instance.

Case 040 records operators chaining a separate Langflow flow-execution IDOR with this bug, using the IDOR for reconnaissance and this endpoint for execution.

The rubric rating is high: the vulnerable path is reachable under the default auto-login configuration, and compromise exposes the credentials and data of every flow on the instance.

## Mitigation

Upgrade to Langflow 1.9.0 or later. The advisory's recommended fix removes the `data` parameter from the endpoint so that public flows run only the definition stored in the database. The advisory lists no workaround. Until the upgrade is applied, instances should not expose Langflow to untrusted networks, and `AUTO_LOGIN` should be disabled.

Authentication was the wrong place to look for the defect: an endpoint intended for anonymous callers must treat every field of the request as hostile, including the ones that appear to configure what it runs.
