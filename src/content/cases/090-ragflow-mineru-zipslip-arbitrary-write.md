---
caseId: "090"
title: "RAGFlow's MinerU parser trusted zip entry names and wrote them wherever they pointed"
filed: "2026-08-29"
filedDisplay: "29 Aug 2026"
firstObserved: "27 Jan 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "RAGFlow, MinerU document-parser integration (deepdoc/parser/mineru_parser.py, version 0.23.1 and earlier; only reachable where mineru_server_url points at an external MinerU conversion service)"
cve: "CVE-2026-24770 (GHSA-v7cf-w7gj-pgf4)"
readTime: "4 min read"
related: ["091", "019", "002"]
---

## Summary

RAGFlow can offload document conversion — turning a PDF or Office file into structured text for retrieval — to an external MinerU service, then downloads the result as a ZIP archive and unpacks it locally. The unpacking routine wrote each archive entry to disk using its name from the ZIP header, unmodified, without confirming the resolved path stayed inside the intended extraction directory. An archive entry named with enough `../` segments landed outside that directory, anywhere the RAGFlow process could write. The flaw was reported and fixed in January 2026; the RAGFlow application surface it sits inside came under renewed attention seven months later, when Microsoft reported observing intrusions against internet-facing RAGFlow deployments in August 2026 — though Microsoft did not attribute that campaign to this specific CVE.

## What was observed

The vulnerable function, `_extract_zip_no_root` in `deepdoc/parser/mineru_parser.py`, iterated over a ZIP archive's members and built each output path with a plain `os.path.join(extract_to, path)`, where `path` came directly from the archive's own filename field:

```
# deepdoc/parser/mineru_parser.py — illustrative
full_path = os.path.join(extract_to, path)   # path is attacker-controlled, unvalidated
with open(full_path, "wb") as f:
    f.write(zip_ref.read(filename))
```

`os.path.join` does not strip `..` segments — it resolves them, the same way a shell would. An archive containing a member named `../../../../deepdoc/parser/mineru_parser.py` or a path under the RAGFlow process's own site-packages directory caused the extraction to overwrite that file instead of writing inside the scratch directory the code intended. Overwriting a module RAGFlow imports on startup, or a script a scheduled job later executes, converts the write primitive into code execution the next time that code path runs, with the privileges of the RAGFlow service account. Reaching the vulnerable extractor required RAGFlow to fetch the malicious archive from wherever `mineru_server_url` pointed — either because that endpoint was itself malicious or compromised, or because an attacker held a network position (DNS manipulation, an on-path host) able to substitute a response for the configured MinerU server. That's a real but non-default precondition: it is not the same as an anonymous request straight to RAGFlow's own listening port doing the damage unassisted.

## Mitigation

RAGFlow's maintainers fixed the extractor in commit `64c75d5`, which resolves each entry's absolute path first and rejects any that fall outside the target directory before writing — the standard Zip Slip remediation. Deployments should update past 0.23.1 and, independently, restrict `mineru_server_url` to a specific, internally-controlled MinerU instance rather than any address an operator or a workflow might configure, and block egress from the RAGFlow host to arbitrary external hosts. The publicized CVSS score of 9.8 treats this as trivially network-reachable and unauthenticated, which is accurate for the write primitive itself but skips over the precondition that RAGFlow has to be pointed at, or intercepted en route to, an attacker-influenced MinerU endpoint first — a real barrier in deployments where that URL is a fixed operator setting rather than something a workflow author can redirect. That gap between "the code executes with no checks" and "an attacker can reach the code" is why this file rates the mechanism medium rather than matching the published critical rating; it would move back toward high in any deployment that lets ordinary users configure or influence the MinerU endpoint per workflow. The broader lesson holds regardless of that precondition: any code that extracts an archive from a network source — self-hosted parsing sidecar or not — needs to canonicalize output paths before writing, the same discipline this database has already logged for backup-restore endpoints (case 019) and file uploads (case 045) elsewhere in the RAG stack.
