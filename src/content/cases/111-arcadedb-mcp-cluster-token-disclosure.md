---
caseId: "111"
title: "ArcadeDB's MCP settings tool leaked the cluster token that unlocks root"
filed: "2026-09-09"
filedDisplay: "09 Sep 2026"
firstObserved: "02 Aug 2026"
severity: high
category: "Disclosure failure"
status: "Patched"
affectedSystems: "ArcadeDB (Maven com.arcadedb:arcadedb-server, < 26.7.3), MCP get_server_settings tool; requires arcadedb.ha.clusterToken (HA_CLUSTER_TOKEN) explicitly configured"
cve: "CVE-2026-67357 (GHSA-p9wc-4fhr-78wm); shares its root cause with the unauthenticated HTTP endpoint variant GHSA-46hj-24h4-j8gf, fixed one release earlier in 26.7.2"
readTime: "5 min read"
related: ["014", "037", "108"]
---

## Summary

ArcadeDB's MCP server exposed a `get_server_settings` tool meant to hand back the database's configuration. Its output only masked keys whose name literally contained the word "password," ignoring the existing internal flag that already marked the HA cluster token as secret. Any authenticated caller who could reach the tool got that token back in cleartext — and the token alone is enough to impersonate the root user against the server's HTTP API. Fixed in 26.7.3.

## What was observed

ArcadeDB supports high-availability clustering, coordinated through a shared secret, `arcadedb.ha.clusterToken`. The server's settings-export code (`exportSettings`) walks every non-database `GlobalConfiguration` key and value and applies exactly one redaction rule: mask it if the key name contains "password." The codebase already had a more general mechanism for this — a per-setting `isHidden()` predicate that correctly flags the cluster token as sensitive — but the export path never called it. The token went out with everything else.

Separately, ArcadeDB's authentication layer treats a request carrying two headers, `X-ArcadeDB-Cluster-Token` and `X-ArcadeDB-Forwarded-User`, as an authenticated request for whatever user the second header names, with no password check, on the theory that only another cluster node would know the token. An authenticated but low-privileged MCP client — scoped to a single database, nothing close to admin — could call `get_server_settings`, read the token out of the response, and replay it with `X-ArcadeDB-Forwarded-User: root` against any admin endpoint: create a user, drop a database, shut the server down.

> The bug isn't that the token exists. It's that a general-purpose redaction check existed in the code and the export function that needed it didn't call it.

This is reachable without HA mode active at all — the export falls back to whatever value the configuration key holds — but it only matters where an operator has explicitly set `HA_CLUSTER_TOKEN`, which happens whenever ArcadeDB is actually run in a cluster rather than standalone. That's a routine production configuration, not an edge case, which is why this is rated on the same footing as the vendor's own advisory rather than discounted for requiring a non-default setting. A near-identical exposure via the raw `GET /api/v1/server` HTTP endpoint was disclosed and fixed in 26.7.2 one release earlier; the MCP-specific tool inherited the same unredacted export function and needed its own follow-up patch.

## Mitigation

Upgrade to ArcadeDB 26.7.3 or later. Operators running earlier versions with clustering configured should rotate `HA_CLUSTER_TOKEN` after upgrading, since any token issued before the patch should be treated as disclosed. More generally: a redaction rule that matches on substring ("contains 'password'") rather than an explicit secret registry will always miss the next field someone adds that isn't named password — cluster tokens, API keys, session secrets. Route all configuration serialization through the one predicate that's actually meant to gate it.
