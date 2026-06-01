# HARNESS.md — Agent Session Lifecycle

> This file governs HOW the agent works. `AGENTS.md` governs WHAT the agent knows.
> Read this file at the start of every session.

---

## Session Lifecycle

```
START
  1. Run: bash init.sh
  2. Read: claude-progress.md (what happened last time)
  3. Read: feature_list.json (what's done, what's next)
  4. Check: git log --oneline -5 (recent changes)

SELECT
  5. Pick exactly ONE feature with status "not-started" or "in-progress"
  6. Announce which feature you're working on

EXECUTE
  7. Implement the feature
  8. Run verification (tests, lint, type-check)
  9. If verification fails → fix and re-run
  10. If verification passes → record evidence

WRAP UP
  11. Update claude-progress.md (what you did, what's next)
  12. Update feature_list.json (change status if done)
  13. Record anything broken or unverified
  14. Commit only when tests pass
  15. Leave clean restart path for next session
```

---

## Rules

1. **One feature at a time.** Never work on two features simultaneously.
2. **Don't declare victory without evidence.** Tests must pass. Lint must be clean.
3. **Don't modify feature_list.json to hide failures.** If something doesn't work, say so.
4. **Update progress log every session.** The next session depends on it.
5. **Commit only clean state.** If tests fail, don't commit. Fix first.

---

## Verification Commands

```bash
# Python SDK
make lint              # flake8 + black --check + pylint
make test              # pytest -n auto

# API
cd api && uv run pytest

# UI
cd ui && pnpm lint && pnpm test

# Full stack smoke test
docker compose up -d
curl -s http://localhost:8080/api/v1/health | grep -q ok
```

---

## File Map

| File | Purpose |
|------|---------|
| `HARNESS.md` | This file — session lifecycle rules |
| `AGENTS.md` | Project knowledge, skills, conventions |
| `init.sh` | Environment health check (run first) |
| `feature_list.json` | Scope boundaries — what to build |
| `claude-progress.md` | Session memory — what was done |

---

## When to Start Services

Only start Docker services if your task requires them:
- **CSPM checks / API work** → `docker compose up -d postgres valkey`
- **Attack paths / graph work** → add `neo4j`
- **Full stack** → `docker compose -f docker-compose-dev.yml up`
- **UI only** → `cd ui && pnpm dev`

---

## Handoff Template

When ending a session, append to `claude-progress.md`:

```markdown
## Session NNN — YYYY-MM-DD

**Focus:** [feature ID + name]
**Status:** ✅ Complete | 🔄 In Progress | ❌ Blocked

### What was done
- ...

### Current state
- ...

### What's next
- ...

### Known issues
- ...
```
