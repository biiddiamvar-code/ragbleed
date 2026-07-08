---
caseId: "004"
title: "A crafted prompt template can read arbitrary files off the server"
filed: "2026-03-30"
filedDisplay: "30 Mar 2026"
firstObserved: "27 Mar 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "langchain-core, prompt-loading API (langchain_core/prompts/loading.py)"
cve: "CVE-2026-34070"
readTime: "4 min read"
related: ["005", "001", "002"]
---

## Summary

LangChain's prompt-loading API accepted a file path as part of a prompt template configuration without validating that the path stayed inside the intended directory. A specially crafted template could point the loader at any file the process could read.

## What was observed

Loading a prompt template from disk is a routine operation — teams check templates into version control and load them by path at runtime. The loader trusted that path without checking whether it resolved outside the expected templates directory. A template built with `../` sequences, or an absolute path, was followed exactly as given, letting the loader return the contents of any file the application process had permission to read — configuration files, credentials mounted into a container, or anything else on the same filesystem.

```
# template config accepted as-is, no path normalization
template_path: "../../../../etc/passwd"
```

Compared to the other cases filed this quarter, this one requires the attacker to already have some ability to supply or influence which template gets loaded — either through an exposed configuration surface or a pipeline that accepts template paths from a less-trusted source. That condition keeps it out of High, but it's a real path to reading sensitive files in any deployment where template selection isn't fully trusted.

## Mitigation

Upgrade langchain-core to the patched release, which validates and normalizes template paths before resolving them. Independently of the patch, never accept a prompt template path from user input or an external source without resolving it against an allowlisted base directory first — the same rule that applies to any file path a web application accepts.
