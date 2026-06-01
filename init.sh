#!/usr/bin/env bash
# init.sh — Run at the START of every agent session.
# Verifies environment health before any work begins.
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

check() {
  if eval "$2" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $1"; ((PASS++))
  else
    echo -e "  ${RED}✗${NC} $1"; ((FAIL++))
  fi
}

warn() {
  if eval "$2" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $1"; ((PASS++))
  else
    echo -e "  ${YELLOW}⚠${NC} $1 (optional)"; ((WARN++))
  fi
}

echo "═══════════════════════════════════════════"
echo " prowler-cnapp — Session Init"
echo "═══════════════════════════════════════════"
echo ""

# --- 1. Prerequisites ---
echo "▸ Prerequisites"
check "git available" "command -v git"
check "docker available" "command -v docker"
check "docker compose available" "docker compose version"
check "python3 available" "command -v python3"
warn  "uv available" "command -v uv"
warn  "node available" "command -v node"
echo ""

# --- 2. Repository state ---
echo "▸ Repository"
check "on a git branch" "git rev-parse --abbrev-ref HEAD"
check "working tree clean" "test -z \"\$(git status --porcelain)\""
check ".env file exists" "test -f .env"
check "feature_list.json exists" "test -f feature_list.json"
echo ""

# --- 3. Services ---
echo "▸ Services (docker compose)"
warn  "postgres running" "docker compose ps --status running | grep -q postgres"
warn  "valkey running" "docker compose ps --status running | grep -q valkey"
warn  "neo4j running" "docker compose ps --status running | grep -q neo4j"
echo ""

# --- 4. Python environment ---
echo "▸ Python"
warn  "uv.lock exists" "test -f uv.lock"
warn  "prowler importable" "python3 -c 'import prowler' 2>/dev/null"
echo ""

# --- 5. Summary ---
echo "═══════════════════════════════════════════"
TOTAL=$((PASS + FAIL + WARN))
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} / ${TOTAL} checks"
if [ "$FAIL" -gt 0 ]; then
  echo -e " ${RED}⚠ Fix failures before starting work.${NC}"
  exit 1
fi
echo -e " ${GREEN}✓ Environment ready. Begin work.${NC}"
echo "═══════════════════════════════════════════"
