---
name: portfolio-review
description: Use when producing a read-only operator portfolio review from Hermes while keeping Kraken Bot V2 as the only live execution authority.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [portfolio, operator-review, kraken-bot, openclaw-decommission, safety]
    related_skills: [hermes-agent, runtime-service-audit]
---

# Portfolio Review

## Overview

Use this skill to produce a bounded, read-only operator portfolio review from Hermes. The goal is situational awareness: summarize current portfolio/risk posture, surface verification gaps, and recommend safe operator next steps.

Hermes is the operator/control-plane layer. Kraken Bot V2 remains the only live execution authority. This skill must never place orders, write overrides, mutate configuration, alter `.env`, change launchd services, or modify live bot behavior.

OpenClaw is legacy advisory/reporting context only. Treat OpenClaw outputs as optional comparison material, not as execution authority.

## When to Use

Use this skill when the operator asks for:

- A portfolio review.
- Current trading posture or exposure summary.
- A read-only sanity check of Kraken Bot runtime artifacts.
- A Hermes-native replacement for legacy OpenClaw operator reporting.
- Assumptions and verification gaps before making trading-system decisions.

Do not use this skill for:

- Placing, cancelling, or replacing orders.
- Writing Kraken Bot overrides or promotion files.
- Editing `.env`, launchd plists, live bot code, risk gates, or execution config.
- Deleting or migrating OpenClaw.
- Long autonomous investigations or filesystem-wide scans.

## Required Safety Boundary

Always preserve these boundaries:

1. **Kraken Bot V2 is the only live execution authority.**
2. **Hermes output is advisory/operator-facing only.**
3. **No override writes.**
4. **No config mutation.**
5. **No `.env` edits.**
6. **No launchd changes.**
7. **No live order actions.**
8. **No direct replacement of Kraken Bot risk or promotion logic.**

If the operator asks for a risky action, stop and ask for explicit approval with a narrow scope.

## CURRENT_STATE-First Procedure

1. Identify the repository scope.
   - Hermes workspace docs normally live in the Hermes repo.
   - Kraken Bot V2 runtime/source should be inspected only if required for the review.
   - OpenClaw should be treated as legacy reference only.
2. Check git status for referenced repos before edits or source inspection summaries.
3. Read context in this order where present:
   - `docs/AI_OPERATOR_RULES.md`
   - `docs/CURRENT_STATE.md`
   - `docs/LATEST_AGENT_LAB.md`
   - `docs/task_context/*`
   - `AGENTS.md` and workspace adapter docs
4. If generated state appears stale, stop and tell the operator exactly which command to rerun:
   - `make current-state`
   - `make task-context/prompt-context`
   - `make semantic-index PROJECT=<project>`
5. Do not rely on generated summaries alone if source files or runtime artifacts contradict them.

## Bounded Inspection Rules

Default bounds:

- Inspect at most 8 files initially.
- Use repo-scoped paths only.
- No filesystem-wide scans.
- No recursive repo crawling.
- Avoid logs unless explicitly required.
- Avoid runtime artifacts unless the review question requires current holdings, balances, open orders, or recent decisions.
- Prefer targeted reads over broad searches.

If more context is necessary, state what is missing and ask for scope expansion.

## Runtime Artifacts: Read-Only and Only When Necessary

When a portfolio review requires current runtime data, inspect only the narrowest relevant Kraken Bot artifacts, for example:

- `data/state.json` for tracked positions and bot state.
- `data/portfolio_snapshot.json` for current portfolio snapshot.
- `data/open_orders_snapshot.json` for open-order posture.
- `data/telegram_status.json` for operator-facing status.
- Recent candidate/verdict artifacts only when explaining why entries were or were not considered.

Do not write to any `data/` path. Do not edit overrides, config, `.env`, or state.

## Output Format

Produce a concise operator review with these sections:

1. **Scope and sources**
   - Repositories and files/artifacts inspected.
   - Whether generated context was present and fresh.
2. **Portfolio posture**
   - Holdings/exposure summary if available.
   - Cash/open-order posture if available.
   - Any missing data clearly labeled.
3. **Risk and safety observations**
   - Existing safety gates observed from source/config/context.
   - No claims about live behavior unless verified from source or current artifacts.
4. **Operator-relevant findings**
   - Items that require attention.
   - Items that are informational only.
5. **Assumptions**
   - Explicit assumptions made because data was unavailable or out of scope.
6. **Verification gaps**
   - What was not inspected.
   - What command or artifact would close the gap.
7. **Safe next steps**
   - Read-only or PR-based follow-ups first.
   - Escalate risky operations separately.

## Common Pitfalls

1. **Treating Hermes as an executor.** Hermes may summarize and advise, but must not place trades or mutate live bot behavior.
2. **Over-reading runtime artifacts.** Only inspect artifacts necessary for the operator question.
3. **Trusting generated context over source.** Generated state is advisory; source/config/runtime artifacts win on conflict.
4. **Forgetting stale context handling.** If CURRENT_STATE or task context is stale, stop and name the refresh command.
5. **Conflating OpenClaw with authority.** OpenClaw is legacy advisory/reporting context only.
6. **Hiding uncertainty.** Always include assumptions and verification gaps.

## Verification Checklist

Before finalizing a portfolio review:

- [ ] Read `docs/CURRENT_STATE.md` first when present.
- [ ] Kept inspection within bounded file/artifact limits or got approval to expand.
- [ ] Did not write overrides, configs, `.env`, launchd files, runtime state, or live bot code.
- [ ] Did not place/cancel/replace orders.
- [ ] Listed all inspected sources.
- [ ] Labeled assumptions and verification gaps.
- [ ] Preserved Kraken Bot V2 as the only live execution authority.
