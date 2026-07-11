---
caseId: "009"
title: "n8n's webhook file handler could be tricked into serving files meant for an AI chatbot's knowledge base"
filed: "2026-01-09"
filedDisplay: "09 Jan 2026"
firstObserved: "07 Jan 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "n8n, form-webhook file handling (versions prior to 1.121.1 / 1.120.4)"
cve: "CVE-2026-21858 (\"Ni8mare\")"
readTime: "5 min read"
related: ["006", "002", "004"]
---

## Summary

n8n's form-webhook handler processed uploaded files without first confirming the request was actually a file upload. By sending a request with the wrong content type, an attacker could substitute a path to any file on the server for the uploaded file's contents — including files a workflow had wired up to feed an AI chatbot's knowledge base.

## What was observed

A common n8n pattern connects a public form to a workflow: someone uploads a document, and a downstream node — often a chatbot node — reads it and answers questions about it. The vulnerable function assumed every request hitting it was multipart form data and read `req.body.files` on that assumption, without checking the content type first.

```
# copyBinaryFile() trusted req.body.files unconditionally
# a non-multipart request could substitute an arbitrary local path here
```

Sending a request with a different content type let an attacker control that files object directly — including the filepath field. Instead of copying the bytes a user actually uploaded, the workflow copied whatever local file the attacker named. Every node downstream of the form, including a chatbot node built to summarize or answer questions about "the uploaded document," would receive that file's contents instead — configuration files, credentials, anything the n8n process could read.

Here's where the rating gets more interesting than the headline CVSS score suggests. This scored a maximum 10.0, and unauthenticated file access is genuinely serious. But turning it into something exploitable required a fairly specific setup already existing: a form-based workflow, publicly reachable without login, with a downstream node that reads and exposes the file's contents somewhere an attacker could see them — like a chatbot that echoes back what it read. Scans for that specific combination found it present on a small fraction of exposed instances. That gap between "maximum severity" and "exploitable in practice" is exactly the distinction our severity rubric exists to draw out.

## Mitigation

Upgrade to n8n 1.121.1 / 1.120.4 or later, which validates content type before trusting the files object. If you run form-based workflows that feed uploaded documents into an AI or chatbot node, audit whether that workflow is publicly reachable without authentication — that combination is the actual risk surface, not the vulnerability in isolation. Treat any file-ingestion node connected to a public entry point as a path worth reviewing on its own, independent of this specific patch.
