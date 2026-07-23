---
caseId: "024"
title: "AutoGPT treated its Redis cache as trusted — poisoning one key bought code execution"
filed: "2026-05-22"
filedDisplay: "22 May 2026"
firstObserved: "18 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "AutoGPT platform (versions 0.6.34 through 0.6.51)"
cve: "CVE-2026-33233"
readTime: "4 min read"
related: ["023", "002", "006"]
---

## Summary

AutoGPT's backend cached values in Redis using Python's `pickle` format and read them back with `pickle.loads()` — a function that doesn't just reconstruct data, it can execute arbitrary code embedded in the serialized bytes. Nothing checked that a cached value's contents actually came from AutoGPT's own write path rather than from anyone who could write to that same Redis key.

## What was observed

Pickle is Python's native serialization format, and it's more powerful than a data format has any need to be: a crafted pickle stream can encode a callable object and its arguments, which get executed the moment the stream is deserialized. That's fine when the only thing ever writing to a given store is your own trusted code. AutoGPT's backend read cache values with `pickle.loads()` and applied no integrity check — no signature, no HMAC, nothing confirming the bytes hadn't been substituted — before trusting them enough to execute.

```
# write path
redis.set(cache_key, pickle.dumps(value))

# read path — no signature or authenticity check
value = pickle.loads(redis.get(cache_key))
# a substituted payload's __reduce__ method runs on load
```

Anyone able to write to a shared cache key AutoGPT's backend reads from — through direct Redis exposure, reused credentials, or a compromised co-tenant on a shared Redis instance — could substitute a payload whose `__reduce__` method returns something like `os.system` with attacker-chosen arguments. The next time the backend read that key, the payload executed with the backend container's own privileges.

The deeper issue here isn't unique to AutoGPT: it's the recurring pattern of treating a cache or message broker as an implicitly trusted boundary rather than as untrusted input that happens to arrive over infrastructure you also control. The same shape of bug — pickle deserialization of data from a shared, writable store — has surfaced repeatedly across the AI serving ecosystem, including inference frameworks handling model weights and RPC messages over similarly "internal" channels.

## Mitigation

Upgrade to AutoGPT platform 0.6.52 or later. Independent of this specific fix: never deserialize pickle data from a store that more than one trust boundary can write to, full stop. If you need to cache structured data across services, use a format that can't encode executable behavior (JSON, MessagePack) or, if pickle is unavoidable for legacy reasons, sign every payload with an HMAC keyed to a secret the writing service holds, and verify that signature before deserializing anything.
