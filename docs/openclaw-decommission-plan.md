# OpenClaw Decommission Plan

## Purpose

Move operator/control-plane responsibility to Hermes while preserving Kraken Bot V2 as the only live execution authority. OpenClaw remains a referenced legacy advisory/reporting repo until each responsibility is replaced by bounded, auditable Hermes-native workflows.

This plan is intentionally governance-first. It does not migrate order placement, override promotion, risk gates, or live trading behavior into Hermes.

## Current Architecture

- **Kraken Bot V2** is the live execution authority.
  - Owns live order placement, position management, TP/reconciliation behavior, risk gates, state mutation, and exchange credentials.
  - Reads its own runtime state and artifacts.
  - Must continue to enforce live-trading safety gates independently of any advisory layer.
- **OpenClaw** is legacy advisory/reporting capability.
  - May produce reports, analysis, and advisory artifacts.
  - Must not be treated as a control-plane dependency for new work.
  - Must not be modified or deleted during this phase.
- **Hermes** is the bounded operator/control-plane layer.
  - Provides Telegram operator interaction, skills, memory, terminal/file tools, Codex/GitHub workflow, workspace rules, and documentation.
  - Produces reviews, summaries, operator checklists, and migration governance artifacts.
  - Must not directly control live execution or write Kraken Bot override/promotion files.

## OpenClaw Responsibilities Still Remaining

These responsibilities may still be referenced while replacements are built:

1. Advisory/report generation for operator context.
2. Historical context about previous trading-analysis experiments.
3. Legacy task/context material that may explain why prior gates or reports exist.
4. Optional comparison baseline for Hermes-native portfolio review output.

OpenClaw is not the source of truth for live execution. If OpenClaw summaries conflict with Kraken Bot source/config/state, prefer the Kraken Bot source/config/state.

## Hermes-Native Replacement Path

1. **Governance and workspace rules**
   - Add CURRENT_STATE-first and bounded-investigation rules to Hermes-side docs and `AGENTS.md`.
   - Require source-first verification before acting on generated summaries.
2. **Operator review skill**
   - Add a Hermes-native `portfolio-review` skill that reads current state first, inspects Kraken Bot runtime artifacts only when necessary, and produces a read-only operator review.
3. **Read-only artifact adapters**
   - Define explicit allowlists for read-only Kraken Bot artifacts if future portfolio-review automation needs them.
   - Keep writes to configs, overrides, launchd, env files, and live bot code out of scope unless explicitly approved.
4. **Advisory parity checks**
   - Compare Hermes operator reviews against legacy OpenClaw reports for completeness, not execution control.
5. **Retirement of legacy reporting**
   - Disable references to OpenClaw reports only after Hermes reviews provide equivalent operator visibility and rollback is documented.

## Explicit Non-Goals

- No live order placement from Hermes.
- No migration of Kraken Bot execution logic into Hermes.
- No write access from Hermes advisory workflows to Kraken Bot override, promotion, config, `.env`, launchd, or state files.
- No OpenClaw deletion or repository restructuring.
- No change to Kraken Bot V2 live behavior.
- No replacement of override/promotion logic in this phase.
- No filesystem-wide crawling, unbounded searches, recursive tool loops, or long autonomous investigations.

## Decommission Phases

### Phase 0: Guardrails

- Document bounded operator mode.
- Update workspace rules.
- Create the read-only portfolio-review skill spec.
- Validate that changes are documentation/skill-only.

### Phase 1: Read-Only Hermes Reviews

- Run operator portfolio reviews from Hermes using CURRENT_STATE-first workflow.
- Inspect Kraken Bot runtime artifacts only when the review question requires them.
- Record assumptions and verification gaps in each review.
- Keep OpenClaw available as a legacy comparison source.

### Phase 2: Advisory Parity

- Compare Hermes review coverage against legacy OpenClaw advisory/reporting outputs.
- Add missing read-only sections to the skill or docs.
- Keep all live execution authority in Kraken Bot V2.

### Phase 3: Operator Cutover

- Make Hermes review output the primary operator-facing report.
- Keep OpenClaw available for rollback/reference.
- Require explicit approval before removing or disabling any legacy operational hook.

### Phase 4: Legacy Retirement

- Remove or archive OpenClaw dependencies only after:
  - Hermes reviews are repeatable and audited.
  - Kraken Bot V2 safety gates remain independently verified.
  - A rollback path exists.
  - The operator explicitly approves retirement.

## Rollback Strategy

- Revert Hermes documentation/skill changes via git.
- Continue using Kraken Bot V2 unchanged; it remains the execution authority throughout.
- Keep OpenClaw untouched during early phases, so legacy reports remain available.
- If Hermes reviews produce incomplete or misleading output, mark them advisory-only and fall back to manual Kraken Bot source/runtime inspection.
- Do not roll back by granting Hermes live execution authority.

## Validation Checklist

- [ ] Hermes git diff contains only docs, workspace instructions, and skill spec changes.
- [ ] OpenClaw repository is unchanged by this migration step.
- [ ] Kraken Bot V2 repository is unchanged by this migration step.
- [ ] `AGENTS.md` preserves CURRENT_STATE-first and bounded-investigation rules.
- [ ] `skills/portfolio-review/SKILL.md` has valid skill frontmatter.
- [ ] Portfolio-review skill explicitly forbids override writes, config mutation, `.env` edits, launchd changes, and live execution.
- [ ] No secrets, runtime logs, exchange credentials, or live state mutations are introduced.
- [ ] Any future risky operation has an explicit escalation/approval requirement.
