---
caseId: "019"
title: "Weaviate's backup restore could be tricked into writing files outside its own directory"
filed: "2025-12-15"
filedDisplay: "15 Dec 2025"
firstObserved: "12 Dec 2025"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Weaviate OSS (versions before 1.33.4)"
cve: "CVE-2025-67818"
readTime: "4 min read"
related: ["004", "011", "009"]
---

## Summary

Weaviate's backup and restore feature reconstructs a collection from stored entries, including whatever name each entry was given at backup time. The restore logic never checked that an entry's name stayed inside the intended restore directory — a name crafted as an absolute path, or with parent-directory traversal sequences, was honored exactly as written when Weaviate wrote it back to disk.

## What was observed

Anyone with permission to insert data into the database could set an entry's name to something like `/etc/cron.d/malicious` or a relative path built from repeated `../` sequences. That name traveled untouched through the backup process and into the restore path. When a backup was restored, Weaviate wrote the entry to the literal path its name specified rather than confining it to the restore root — creating or overwriting a file anywhere within the application's own privilege scope.

```
# entry name used directly as a restore path, no confinement
entry_name = "../../../../etc/cron.d/task"
# restore writes to that literal path instead of the intended directory
```

This isn't a bug reachable by an anonymous outsider — it requires the kind of access most deployments already gate behind authentication: the ability to write data into the database in the first place. That's exactly why it's rated the way it is here rather than as a maximum-severity finding: the barrier to exploitation is real, even though what's reachable past that barrier — arbitrary file creation or overwrite — is serious. A backup/restore cycle is also something administrators run routinely, often without re-auditing the data that's about to be restored, which is what makes this worth flagging rather than dismissing as "just needs existing access."

## Mitigation

Upgrade to Weaviate 1.33.4 or later, which confines restore operations to the intended directory regardless of what an entry's stored name contains. Independent of the patch, treat backup restoration the same way you'd treat any file-extraction operation on untrusted archive contents: validate that every resulting path resolves inside the expected root before writing, and audit who holds data-insert privileges on any instance where backups are taken and restored across trust boundaries — for example, restoring a backup captured from a less-trusted environment into a more sensitive one.
