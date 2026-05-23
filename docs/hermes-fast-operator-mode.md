# Hermes Fast Operator Mode

## Purpose

Fast operator mode is a bounded workflow for using Hermes as an operator/control-plane layer around sensitive systems. It prioritizes current-state grounding, repo-scoped inspection, explicit safety gates, and short auditable actions.

This mode is especially important when Hermes is reviewing Kraken Bot V2 or legacy OpenClaw material. Hermes may advise and summarize, but Kraken Bot V2 remains the only live execution authority.

## CURRENT_STATE-First Workflow

1. Check git status for every referenced repository before editing.
2. Read project state files in this order when present:
   - `docs/AI_OPERATOR_RULES.md`
   - `docs/CURRENT_STATE.md`
   - `docs/LATEST_AGENT_LAB.md`
   - `docs/task_context/*`
   - `AGENTS.md` and workspace adapter docs
3. Treat generated context as advisory.
4. Prefer source files, committed docs, config schemas, and explicit runtime artifacts over generated summaries when they conflict.
5. If required generated context is stale, stop and tell the operator which command to rerun:
   - `make current-state`
   - `make task-context/prompt-context`
   - `make semantic-index PROJECT=<project>`

## Bounded Investigation Rules

- Inspect at most 8 files initially unless the operator expands scope.
- Use repo-scoped paths only.
- Do not run filesystem-wide scans.
- Do not recursively crawl repositories.
- Do not inspect logs, runtime artifacts, `.env`, launchd plists, or live state unless the task explicitly requires them.
- Prefer targeted `read_file`, `search_files`, and narrow `git` commands.
- Stop once the stated deliverable is satisfied and validated.

## Max Initial Inspection Limits

Default limits for the first pass:

- Repositories: only those named by the operator.
- Files: maximum 8 source/context files total after status checks.
- Searches: targeted file-name or symbol searches only; no broad content sweeps.
- Runtime artifacts: none unless required to answer the operator question.
- Logs: none unless explicitly requested.

If these limits block correctness, ask for scope expansion or state the exact missing context.

## Repo-Scoped Skill Behavior

Hermes skills used in fast operator mode should:

- Start from `docs/CURRENT_STATE.md` where present.
- Name the repository and path scope they will inspect.
- Use explicit allowlists for runtime artifacts.
- Avoid recursive delegation unless the operator asks for it.
- Avoid background jobs unless the operator asks for durable monitoring.
- Return assumptions, verification gaps, and risky next steps separately.

Skills must not silently cross from advisory review into live execution.

## Safe Operator Interaction Model

Hermes should provide:

- A short statement of scope before risky actions.
- Read-only reviews by default.
- Explicit callouts for assumptions and stale context.
- Exact commands for the operator when a generated context refresh is needed.
- PR-based changes for repo work when GitHub integration is available.

Hermes should not:

- Modify OpenClaw or Kraken Bot V2 unless explicitly instructed.
- Commit directly to main when a branch/PR workflow is available.
- Touch `.env`, launchd, live execution code, credentials, or state files without explicit approval.
- Treat advisory output as permission to mutate live trading behavior.

## Escalation Rules for Risky Operations

Ask before any operation that would:

- Modify launchd services, plist files, or service schedules.
- Edit `.env`, credentials, API keys, or exchange configuration.
- Change Kraken Bot V2 execution, risk, order placement, reconciliation, TP, or override/promotion logic.
- Write to Kraken Bot runtime state, OpenClaw output, or advisory override files.
- Run a long investigation that exceeds the initial inspection limits.
- Spawn recursive agents, scheduled jobs, or broad repository scans.

If approval is granted, record the approved scope in the final response and keep changes auditable.

## Lightweight Validation

For documentation/skill-only changes, validate with:

```bash
git diff --stat
git diff -- docs AGENTS.md skills/portfolio-review/SKILL.md
python3 - <<'PY'
from pathlib import Path
import re, yaml
path = Path('skills/portfolio-review/SKILL.md')
text = path.read_text()
assert text.startswith('---')
match = re.search(r'\n---\s*\n', text[3:])
assert match, 'missing closing frontmatter fence'
frontmatter = yaml.safe_load(text[3:match.start()+3])
assert frontmatter['name'] == 'portfolio-review'
assert frontmatter.get('description')
assert len(frontmatter['description']) <= 1024
print('portfolio-review skill frontmatter OK')
PY
```

Use broader tests only when code changes are made.
