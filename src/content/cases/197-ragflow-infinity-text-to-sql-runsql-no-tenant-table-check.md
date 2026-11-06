---
caseId: "197"
title: "RAGFlow's text-to-SQL retrieval on the Infinity engine ran model-generated SQL without table-ownership checks, leaving the tenant boundary in the prompt alone"
filed: "2026-11-06"
filedDisplay: "06 Nov 2026"
firstObserved: "03 Nov 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "infiniflow RAGFlow 0.27.0-0.27.2 and 1.0.0-rc1-rc2, with DOC_ENGINE=infinity (range per CVE record; exact range not established by the researcher)"
cve: "CVE-2026-121585 (CNA: VulDB, CVSS 4.0 5.3; researcher self-scored CVSS 3.1 8.5)"
readTime: "4 min read"
related: ["176", "143", "196"]
---

## Summary

CVE-2026-121585 records an authorization bypass in the `RunSQL` function of RAGFlow's Text To SQL retrieval component. On deployments using the Infinity document engine, the SQL produced by the language model was executed without checking which tables it referenced, so one tenant's knowledge-base table could be queried from another tenant's chat. No fixed release was identified, and the end-to-end flow was verified by the researcher in separate parts rather than as one run.

## What was observed

The CVE record places the flaw in `internal/engine/infinity/sql.go`, where manipulation of the `tableName` or `kbIDs` arguments bypasses authorization. A public write-up by the researcher describes the mechanism in more detail. A user's question is sent to the model together with a system prompt naming the user's own table. The model returns SQL, and `normalizeSQL()` strips only trailing semicolons. `RunSQL()` then applies cosmetic rewrites and passes the statement to `psql -c`. Nothing checks table ownership, read-only status or row limits. The write-up contrasts this with the vastbase engine, which applies those checks.

```
# user B, regular account, multi-tenant instance, DOC_ENGINE=infinity
# chat question steers the model to emit SQL against ragflow_<tenantA>_<kbA>
# RunSQL passes it to the engine unchanged
# Infinity's PG wire handler: no authentication, all tenants share default_db
```

The write-up states that Infinity's PostgreSQL wire handler performs no authentication and that all tenants' tables share one database, so the application layer was the only boundary. That boundary existed in the prompt, which depends on the model declining to write a cross-tenant query. The researcher reports the model noticed the table mismatch and issued the query anyway. The Infinity port binds to localhost by default and is not exposed in the shipped compose file, so access ran through the application.

Verification is partial. The researcher tested the Infinity connection behaviour and the model's SQL generation separately and did not run the complete flow. The researcher states that the vulnerable version range was not established. The CVE record gives 0.27.0 to 0.27.2 and 1.0.0-rc1 to rc2. Related pull request #15124 adds a read-only SQL guard to chat structured-data queries. It does not address table ownership, and its merge status could not be confirmed. The root cause as described here rests on the CVE record and the researcher's write-up, not on a vendor advisory.

The CNA scored the flaw CVSS 4.0 5.3. The researcher scored it 8.5, or 6.8 if model output is not treated as attacker-controlled. RagBleed rates the mechanism medium: it needs a non-default document engine and a multi-tenant instance, but the data exposed is knowledge-base content from other tenants.

## Mitigation

Check the project's releases for a build later than 1.0.0-rc2 and for a change that binds generated SQL to the caller's own tables. Until then, avoid `DOC_ENGINE=infinity` on multi-tenant instances, or disable the Text To SQL retrieval component. Keep the Infinity port on localhost. Model-generated SQL is untrusted input: the table allow-list and the read-only restriction belong in the execution layer, since a prompt instruction does not enforce either.
