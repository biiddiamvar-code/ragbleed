---
caseId: "124"
title: "unstructured's URL-based partitioning fetched any host a caller named, with no validation at all"
filed: "2026-09-17"
filedDisplay: "17 Sep 2026"
firstObserved: "10 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "unstructured (PyPI, >=0.4.7, <0.24.0)"
cve: "CVE-2026-71428 (GHSA-4mvj-m6j5-pmf7)"
readTime: "4 min read"
related: ["015", "062", "093"]
---

## Summary

`unstructured` is the document-parsing library that sits underneath a large share of the RAG ingestion ecosystem — LangChain's `UnstructuredURLLoader`, LlamaIndex's `UnstructuredReader`, Chainlit, and assorted agent frameworks all hand it a URL and expect back clean, chunked text. Its `partition()`, `partition_html()`, and `partition_md()` functions accept a `url=` argument and fetch it with `requests.get()`. No host, scheme, or address-range check ran before that request went out, and the full response body came back as `Element` text in the parsed output. Any caller who could influence the URL — directly, or indirectly through content the pipeline treats as containing a link to follow — could turn the ingestion step into a full-read SSRF proxy. Fixed in 0.24.0.

## What was observed

The vulnerable code path was small: `url=` in, `requests.get(url)` out, response body in, no intermediate check.

```
# illustrative: pre-fix partition() call
elements = partition(url=user_supplied_url)
# requests.get(user_supplied_url) ran unchecked —
# http://169.254.169.254/latest/meta-data/iam/security-credentials/...
# http://localhost:9200/_cat/indices  (internal Elasticsearch)
# http://internal-admin.svc.cluster.local/  (internal admin panel)
# — all fetched, and the response text returned as parsed document content
```

Because the function's entire purpose is to fetch a URL and hand back its contents as text, there was nothing unusual for a validation layer to distinguish: a request to cloud instance metadata looks, to `requests.get()`, exactly like a request to the public document the caller claimed to want ingested. And because the response is returned as ordinary `Element` text rather than raised as an error or flagged as anomalous, the leaked content flows straight into whatever the calling application does with parsed output — indexing it into a vector store, summarizing it, or showing it back to a user — with no separate exfiltration channel required.

The library sits several layers removed from the application developer's own code, which is precisely what made this a full-read SSRF rather than a narrower blind one: `unstructured` is rarely called directly by an end user. It's invoked by a loader, which is invoked by a chain, which is invoked by an application that may never render its own SSRF guard because it reasonably assumed the parsing library it imported already had one. `unstructured` is the de facto URL-ingestion layer for several major frameworks — secure defaults have to live in the library itself, not be re-implemented by every downstream caller who remembers to add them.

## Mitigation

Upgrade to `unstructured` 0.24.0 or later. Until then, do not pass caller- or document-influenced URLs to `partition()`, `partition_html()`, or `partition_md()` without an application-level allow-list and a block on loopback, link-local, and RFC 1918 address ranges — including after DNS resolution, since a validated hostname can still resolve to an internal address. Any pipeline that lets an end user submit a URL for ingestion, or that follows links discovered inside already-ingested documents, should treat this as a full-read SSRF primitive until confirmed patched. The broader pattern here matches other cases on this site (015, 062, 093): a fetch performed on behalf of a retrieval pipeline is a request from your infrastructure's network position, and every library in the chain that performs one needs its own validation — trusting that some upstream caller already checked is how this class of bug keeps recurring.
