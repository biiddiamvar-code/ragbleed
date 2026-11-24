---
caseId: "223"
title: "vLLM's thinking-budget state holder copied rather than moved per-row state on batch SWAP, aliasing one request's budget onto a co-batched request and forcing the reasoning-end token into its output"
filed: "2026-11-24"
filedDisplay: "24 Nov 2026"
firstObserved: "09 Nov 2026"
severity: low
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (>=0.21.0, <0.28.0), V1 model runner with reasoning enabled and reasoning_end_str configured"
cve: "No CVE assigned as of writing; tracked as GHSA-fpch-3xrf-7q96 (CWE-488, CVSS 3.1 5.3)"
readTime: "4 min read"
related: ["208", "182", "151"]
---

## Summary

vLLM tracked per-request thinking-token budgets in a dictionary keyed by batch row. When the attention backend reordered the batch with a `SWAP`, the state holder read both rows and reassigned them without removing the source key, so a single budget object could end up registered under two rows. When that budget was exhausted, the forcing logic wrote the configured reasoning-end tokens into every registered row, including the row belonging to an unrelated concurrent request. Version 0.28.0 fixes the swap handling.

## What was observed

GitHub advisory GHSA-fpch-3xrf-7q96, published 09 Nov 2026, credits KernelClint as finder and attributes the report to Patch the Planet, a Trail of Bits and OpenAI collaboration. The defect sat in `ThinkingBudgetStateHolder.sync_batch()` in `vllm/v1/sample/thinking_budget_state.py`. Its non-swap branch moved state with `pop`; its `SWAP` branch read both endpoints with `get()` and wrote them back crosswise. If only one of the two rows held thinking-budget state, the swap left that object under the new row and did not remove it from the old one.

```
# Illustrative, vLLM 0.21.0-0.27.x
# before reorder: state = { 3: budget(A) }         row 3 = request A (budgeted), row 5 = request B (none)
# SWAP(3, 5) via get()/reassign, no pop
# after reorder:  state = { 3: budget(A), 5: budget(A) }   row 3 is now request B
# budget(A) exhausted -> _apply_forcing_to_logits() iterates state
#   -> forces think_end_token_ids into row 3 (B) as well as row 5 (A)
```

`_apply_forcing_to_logits()` iterated every row present in the state dictionary and, once the budget phase reached the end-of-reasoning stage, forced `think_end_token_ids` into that row's logits. An aliased row was indistinguishable from a genuinely budgeted one. The advisory points to the logits-processor `process_dict_updates()` swap branch in `builtin.py`, which pops both endpoints, as the correct pattern the state holder had not followed.

Reaching the condition required reasoning support with `reasoning_end_str` set, the V1 model runner, an attention backend whose reorder path emitted a `SWAP`, and a client sending `thinking_token_budget`. The attacker also had to arrange for a budgeted request and a victim request to fall on opposite sides of the swap. The injected content was limited to the operator's configured reasoning-end sequence, such as `</think>`, not arbitrary tokens. The advisory states that no confidentiality impact was demonstrated.

The rating is low, below the advisory's moderate CVSS score. The defect crossed a request boundary, which is the property this site tracks, but what crossed was a fixed, operator-chosen token sequence rather than another user's data, and it depended on a non-default reasoning configuration plus batch timing the attacker could influence but not control. The effect on the victim was a prematurely terminated reasoning phase. The advisory's own vector scores availability rather than integrity, which does not match its description of the impact.

## Mitigation

Upgrade vLLM to 0.28.0 or later, which contains the fix from PR #49613. On affected versions, operators serving multiple tenants can stop accepting `thinking_token_budget` from clients at the gateway, or leave `reasoning_end_str` unset.

Like case 208, this was per-request state that survived a batch-slot reassignment in vLLM's V1 runner. Any structure keyed by batch row index has to treat a reorder as a move, not a copy.
