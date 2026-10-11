---
caseId: "161"
title: "LangChain.js's MongoDB chat history accepted query operators as session identifiers"
filed: "2026-10-11"
filedDisplay: "11 Oct 2026"
firstObserved: "08 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "@langchain/mongodb (npm, < 1.3.1)"
cve: "CVE-2026-106119"
readTime: "3 min read"
related: ["076", "118", "005"]
---

## Summary

`MongoDBChatMessageHistory` in `@langchain/mongodb` did not verify at runtime that the session identifier it received was a string. A structured value carrying MongoDB query operators was interpreted by the database as a query condition instead of a literal ID. Where an application let untrusted input reach the session identifier, a user could read, modify, or delete chat histories belonging to other sessions.

## What was observed

The class stores conversation messages in a MongoDB collection keyed by a session identifier, and looks them up with that identifier as a filter value. TypeScript typing declared the identifier as a string, but nothing enforced the type at runtime. When request data was deserialized from JSON and passed through without validation, an object such as `{ "$ne": null }` arrived in place of a string. MongoDB evaluates operator objects in a filter as query logic, so the lookup matched documents beyond the caller's own session.

```
// intended filter, scoped to one session:
{ sessionId: "alice-1234" }

// attacker supplies sessionId as an object instead of a string:
{ sessionId: { "$ne": null } }
// MongoDB reads this as "any document with a non-null sessionId"
// the lookup is no longer bounded to a single session
```

Exposure depended on deployment shape. The advisory describes the issue as most relevant when several users' histories share one collection and untrusted input reaches the session identifier. Applications that derived the identifier from an authenticated, server-controlled value were not exposed. The same class of flaw, an unvalidated identifier reaching a database filter, was recorded in the MongoDB checkpoint saver for LangGraph.js, which received the same fixed version number.

The advisory rates the flaw at CVSS 6.0 (moderate). RagBleed rates it medium: the mechanism requires an application-level validation gap in addition to the library defect, but the data exposed is private conversation history across users.

## Mitigation

Upgrade to `@langchain/mongodb` 1.3.1 or later, which validates identifiers at runtime and treats them as literal values in the query. Where upgrading is not immediate, reject any session identifier that is not a non-empty string before it reaches the history class, and derive it from an authenticated, server-side value rather than from request fields. Database drivers that accept operator objects in filters make every identifier a potential query fragment; the type check belongs at the boundary where external input enters.
