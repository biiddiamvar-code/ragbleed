---
caseId: "104"
title: "RAGAS's multimodal prompt handling let a crafted URL read local files instead of images"
filed: "2026-09-05"
filedDisplay: "05 Sep 2026"
firstObserved: "01 Apr 2025"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "ragas (PyPI package, v0.2.3 through v0.2.14)"
cve: "CVE-2025-45691"
readTime: "5 min read"
related: ["105", "015", "010"]
---

## Summary

RAGAS is an open-source library used to evaluate retrieval-augmented generation pipelines — scoring properties like faithfulness and context relevance by feeding retrieved passages back through the model under test. Its multimodal prompt handling accepted a URL from that retrieved content and decided whether it pointed at an image using a filename-based guess rather than the fetched content itself. A URL crafted to look like an image while actually pointing at a local file or an internal network address passed that check, and its contents were read, base64-encoded, and returned as if they were image data.

## What was observed

The vulnerable code lived in `ImageTextPromptValue`, the class RAGAS uses to build multimodal prompts out of mixed text and image items pulled from `retrieved_contexts`. Each item was routed through `is_image()` to decide whether to treat it as an image URL or plain text. `is_image()` called `is_valid_url()` — which only checked that a URL had a scheme and a network location, accepting `file://` — and then used Python's `mimetypes.guess_type()` on the full URL string to guess a content type from the filename.

That guess was the flaw. `mimetypes.guess_type()` derives its answer from the string's trailing characters, including anything after a `#` fragment marker — a part of the URL that `urlopen()` itself discards before deciding what resource to fetch. A URL like `file://localhost/etc/passwd#payload.jpg` satisfied `is_valid_url()` (scheme `file`, netloc `localhost`) and made `guess_type()` return `image/jpeg`, because it only saw the `.jpg` tail. The mismatch between what the type-guesser read and what the fetcher actually opened is what let the check pass.

```
item = "file://localhost/etc/passwd#payload.jpg"
# is_valid_url(item)  -> True   (scheme="file", netloc="localhost")
# guess_type(item)    -> image/jpeg  (only sees the "#payload.jpg" tail)
# urlopen(item)        -> opens /etc/passwd; the "#payload.jpg" fragment is ignored
```

Once `is_image()` returned true, `get_image()` handed the URL to `download_and_encode_image()`, which called `urllib.request.urlopen()` directly. `urlopen()` supports the `file://` scheme, resolves the path (dropping the fragment as browsers and URL-handling libraries generally do), and returns the target file's contents, which the function then base64-encoded into the outgoing prompt. The same request pattern reached non-file targets too: a URL such as `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>.jpg` on an AWS host running the older IMDSv1 metadata service returned that role's temporary credentials, again disguised behind a fake image extension.

The precondition is that something outside the evaluator's control gets to populate `retrieved_contexts`. That's a normal, not exceptional, situation for the products RAGAS is built to evaluate: a poisoned document in the knowledge base a RAG system retrieves from, an evaluation dataset pulled from a shared GitHub repo or S3 bucket, or a multi-tenant evaluation API that accepts `retrieved_contexts` directly from customers all put attacker-influenced content in that field before the evaluation run ever starts. None of those require compromising the RAGAS process itself — they only require the ability to influence data the evaluation pipeline was already designed to ingest from less-trusted sources.

## Mitigation

Upgrade to `ragas` 0.3.0-rc1 or later, which corrects the URL and MIME-type validation in the multimodal prompt path. Independent of the patch, treat any function that infers a resource's type from its filename or URL string as unsafe for a security decision — validate the fetched content's actual type, restrict URL schemes to `http`/`https` only, and block requests to loopback, link-local, and cloud-metadata address ranges before the fetch happens, not after. That guidance applies beyond RAGAS to any evaluation, ingestion, or retrieval code that treats "looks like an image filename" as equivalent to "is safe to fetch."
