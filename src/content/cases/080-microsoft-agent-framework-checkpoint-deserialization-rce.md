---
caseId: "080"
title: "Microsoft Agent Framework ran a planted message as code the moment a session was rewound"
filed: "2026-08-22"
filedDisplay: "22 Aug 2026"
firstObserved: "05 Aug 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "Microsoft Agent Framework (Python and .NET SDKs), checkpoint/state-resume feature (agent_framework._workflows._checkpoint_encoding); pre-GA builds audited by Check Point Research through mid-2026, hardened ahead of general availability"
cve: "No CVE assigned; Microsoft did not issue one because the framework had not reached general availability when the flaw was reported. Disclosed by Check Point Research (Shahar Tal, Yarden Porat) at Black Hat USA 2026; Microsoft confirmed the finding, paid a $10,000 bounty, and shipped a fix"
readTime: "5 min read"
related: ["058", "024", "034"]
---

## Summary

Microsoft Agent Framework lets agents save checkpoints — serialized snapshots of conversation state and task progress — so a failed run can resume instead of restarting from scratch. Check Point Research found that the checkpoint loader deserialized this saved state without verifying it was safe to execute, and that message content an attacker had planted earlier in a conversation could ride inside that state. One user's message wrote the payload; a different user rewinding their own session triggered it, handing the attacker a shell on the server. Microsoft fixed the issue and hardened the checkpoint format before the framework reached general availability, but because it wasn't yet a GA product when the bug was found, no CVE was assigned to a flaw that reached a shipping product anyway.

## What was observed

Agent Framework's checkpoint mechanism exists to make long-running or multi-step agent workflows resilient: state gets serialized to persistent storage at intervals, and if a run fails or a user steps away, the framework can reload that state and continue rather than starting over. Check Point's researchers found that the loader trusted the serialized state as much as it trusted a freshly generated one — it deserialized whatever the checkpoint contained and resumed execution against it, without distinguishing state that had passed through attacker-influenced content from state that hadn't.

That distinction mattered because checkpointed state isn't a closed system. It's built, at least in part, from the conversation the agent has been having — including content that arrived from documents, tool outputs, or other users, any of which prompt injection research has spent the past two years demonstrating can be steered by an attacker. Check Point's account of the exploit was direct: a message containing the payload gets absorbed into a session's state, that state gets checkpointed, and later — potentially by an entirely different person, in an entirely different session — a resume operation deserializes the checkpoint and the payload executes.

```
# illustrative: checkpoint resume, pre-fix
state = deserialize(load_checkpoint(session_id))   # trusts stored bytes
agent.resume(state)                                 # executes whatever came back
```

No dangerous tool call was involved, and no one had to click anything. The researchers' framing of the broader talk applies squarely here: "one person's message plants the payload, and then a different person rewinds their own session, which triggers the payload, and now the attacker has a shell on that server." The vulnerability lived entirely in what the framework did with data it had already agreed to trust — its own save-and-reload plumbing — rather than in any tool the agent was given.

Microsoft's response, provided to The Register, was that it had "released protections to harden the Agent Framework and prevent the concrete exploitation path demonstrated in the proof of concept," and updated the checkpoint-encoding module with explicit language defining the security boundary around deserialized state. That fix landed before Agent Framework's general-availability release, which is also why the bug carries no CVE: Microsoft's numbering only covers issues found in shipping products, leaving pre-GA fixes — even ones that closed an unauthenticated RCE path — outside the record entirely.

## Mitigation

Deployments should run current Agent Framework releases, which include the hardened checkpoint-encoding boundary; there is no configuration flag that disables the vulnerable behavior in older builds; the fix is in the deserialization path itself. More broadly, any framework that checkpoints or persists conversational state for later resume needs to treat that stored state as attacker-reachable by default, not as an internal implementation detail — because if a message can end up in the state, and the state gets deserialized and executed on reload, then the message can end up as code. The absence of a CVE here is itself a lesson: pre-GA status let a real remote-code-execution path ship, get fixed, and go unrecorded outside a conference talk and a vendor statement, which is exactly the kind of gap this site exists to close.
