---
caseId: "140"
title: "DBHub's read-only mode read a config value that was never set, leaving a first-keyword check as the only barrier"
filed: "2026-09-27"
filedDisplay: "27 Sep 2026"
firstObserved: "24 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "DBHub (npm @bytebase/dbhub, all versions < 0.22.6), execute_sql tool configured with readonly = true"
cve: "CVE-2026-61788 (GHSA-mwwr-p57h-56pf)"
readTime: "4 min read"
related: ["139", "133", "134"]
---

## Summary

DBHub lets operators mark its `execute_sql` MCP tool as `readonly = true`, which lets an agent query a database without changing it. Before 0.22.6, the connection-level enforcement behind that flag never ran, because it depended on a configuration value that was never populated. Read-only mode rested entirely on a classifier that inspected the first keyword of each statement, and any `SELECT` that wrote data through a function call passed it. Fixed in 0.22.6.

## What was observed

According to the CVE record, DBHub's connectors were written to enforce read-only mode at the database layer. PostgreSQL connections were supposed to set `default_transaction_read_only=on`, and SQLite databases were supposed to open in `readOnly` mode. Both code paths were gated on a config value that no code path ever populated. Operators could set `readonly = true`, and DBHub would accept and display the setting, while every connection stayed fully writable.

The only remaining control was a lexical classifier that looked at the first keyword of each submitted statement and allowed reads such as `SELECT`. That check did not account for side effects. In PostgreSQL, a `SELECT` can call functions that modify state, and the classifier had no way to tell the difference.

```
-- all begin with SELECT; all passed the read-only classifier (illustrative)
SELECT setval('orders_id_seq', 1);          -- ordinary role: sequence tampering
SELECT pg_read_file('/etc/passwd');         -- privileged role: host file read
SELECT lo_export(<oid>, '/path/on/host');   -- privileged role: host file write
```

The record listed a range of outcomes that depended on the database role. With an ordinary role, an attacker could tamper with sequences. With a privileged role, they could write arbitrary files on the database host with `lo_export`, read host files with `pg_read_file`, and reach remote code execution by combining `dblink` with `COPY ... TO PROGRAM`. The record also noted that DBHub's HTTP transport was unauthenticated and bound to `0.0.0.0` by default, so any network caller of `/mcp` could reach the tool directly. A caller did not need to steer an agent with prompt injection.

We rated this medium, below the CNA's CVSS 7.4. The flag failed silently in every deployment that used it, but most of the damage required the operator to have connected DBHub with a superuser or file-privileged role. Under an ordinary role, a caller could only make limited writes through side-effecting functions, which falls short of the rubric's high tier. Deployments that combined the unauthenticated HTTP transport with a privileged role should treat this as high.

## Mitigation

Upgrade to DBHub 0.22.6 or later (fix commit 872bb33). Do not rely on the tool-level `readonly` flag as the only guarantee. Connect DBHub with a database role that has been granted only `SELECT` on the schemas the agent needs, with no superuser, `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`, or large-object privileges. Keep the HTTP transport on loopback or behind an authenticating proxy (see case 139 for the rebinding path to the same endpoint).

A read-only mode that the database itself does not enforce offers weak protection. An application-side parser that inspects SQL text cannot reliably predict what the engine will do with that text.
