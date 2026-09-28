---
caseId: "143"
title: "RAGFlow's Go tenant import endpoints accepted an absolute file_path with no validation, reading server-side JSON files into datasets; a sibling route also trusted the payload's index name across tenants"
filed: "2026-09-28"
filedDisplay: "28 Sep 2026"
firstObserved: "17 Sep 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "RAGFlow (infiniflow/ragflow, all versions through 0.27.2), Go API layer: /api/v1/tenant/dev_insert_chunks_from_file and dev_insert_metadata_from_file (internal/handler/tenant.go)"
cve: "CVE-2026-93013 (file-read path traversal, CNA: VulnCheck); the related cross-tenant chunk write was reported as GitHub issue #19391 with no CVE assigned"
readTime: "4 min read"
related: ["002", "003", "090"]
---

## Summary

RAGFlow's Go API exposes two developer import routes under the tenant handler, `dev_insert_chunks_from_file` and `dev_insert_metadata_from_file`. Both took a `file_path` parameter and opened it on the server without checking where it pointed. Any user with a valid access token could supply an absolute path and have the service read that file. Whatever parsed as the expected JSON structure was then written into a dataset the user could query. The CVE record covers this file read. A separate bug report showed that one of the same routes also skipped the dataset-ownership check and took the target index name from the payload. That allowed chunks to be written into another tenant's index.

## What was observed

CVE-2026-93013, published 17 September 2026, described the flaw as missing path validation. The handler passed the caller-supplied `file_path` directly to a file read. It did not resolve the path against an allowed import directory, and it did not reject absolute paths. The service read anything its own process could open.

Disclosure was indirect and constrained. The routes did not return file bytes. They parsed the file as a chunk or metadata import document and wrote the result into a dataset. Files that did not match the expected JSON shape failed to import. Files that did match were copied into a dataset the attacker could then query through normal retrieval. The CVE record does not list which files on a stock deployment meet that condition. The practical exposure therefore depends on which JSON files a given installation keeps within reach of the service account.

```
# illustrative request shape, not a working exploit
POST /api/v1/tenant/dev_insert_chunks_from_file
Authorization: Bearer <any valid user token>
{ "file_path": "/absolute/path/outside/import/dir.json" }
# handler: read(file_path) -> parse as chunk list -> insert into index
# no path confinement; no ownership check on the target dataset (issue #19391)
```

GitHub issue #19391, filed in September against a nightly build, reported a second defect in `dev_insert_chunks_from_file`. The sibling route `CreateChunkStore` verifies `datasetService.Accessible`, and `InsertMetadataFromFile` scopes writes to the caller's tenant. `dev_insert_chunks_from_file` did neither. It took `knowledgebase_id` and `index_name`/`table_name` from the JSON payload. A logged-in user could therefore write chunks into another tenant's physical index. The reporter confirmed this by driving the real handler: a foreign user's request passed every check and reached the engine insert call, and after the reporter's patch the same request returned 404. The combination gives an authenticated user a read path from the server filesystem and a write path into other tenants' retrieval corpora. The second path is an ingestion-time poisoning primitive.

The CVE record scores the file read at CVSS 4.3 (v3.1) and 5.3 (v4.0) and treats it in isolation. We rated the case medium. Exploitation requires only an ordinary user token, and the related cross-tenant write affects data integrity in multi-tenant deployments. Neither path gives unauthenticated access, and the read is limited to files that parse as import documents, which keeps this below high.

## Mitigation

The CVE record lists two fix commits, aa78e8d and a024bea, along with PR #19591, which close the path-validation gap in the import routes. Neither the CVE record nor OSV names a tagged release containing them, so check that your build postdates those commits before treating an instance as patched. Issue #19391 was still in triage at the time of filing. Operators should not assume the cross-tenant write was fixed by the same change.

Until a confirmed fixed release is deployed, block `/api/v1/tenant/dev_*` at the reverse proxy for all non-administrative callers. Run the RAGFlow service as a user that cannot read deployment secrets or other tenants' export directories. Review datasets for unexpected chunks whose source was an import call rather than a document upload.

Routes prefixed `dev_` were built for developer convenience and then shipped on the same authenticated surface as production APIs. They lacked the checks their production siblings had, and the prefix protected nothing.
