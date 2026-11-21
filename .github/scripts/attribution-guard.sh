#!/usr/bin/env bash
# attribution-guard (Jordan 2026-11-19): fail a change that credits an AI/agent or carries someone else's identity.
# Run inside a full checkout (fetch-depth 0). Inputs (env):
#   EVENT       pull_request | push
#   BASE HEAD   shas; commits judged are BASE..HEAD (push to a new branch: BASE is empty or all zeros, only HEAD is judged)
#   TITLE BODY PR_AUTHOR HEAD_REF   pull_request only
# Fails closed: a git error, a missing sha or an empty range is an error (exit 2), never a pass.
set -u -o pipefail
export LC_ALL=C.UTF-8
EVENT="${EVENT:-pull_request}"
ZERO=0000000000000000000000000000000000000000
JORDAN_NAME='Jordan Allen Lewis'
JORDAN_RE='^(42820601\+jordanallenlewis@users\.noreply\.github\.com|jordanallenlewis@gmail\.com)$'
COMMITTER_OK_RE='^(42820601\+jordanallenlewis@users\.noreply\.github\.com|jordanallenlewis@gmail\.com|noreply@github\.com)$'
TRAILER='^[[:space:]]*(Agent|Requested-by|Co-authored-by|Claude-Session|Generated-by)[[:space:]]*:'
OTHER='generated (with|by)[^a-z]{0,6}(claude|anthropic|chatgpt|codex|gemini|copilot)|signed-off-by[[:space:]]*:[[:space:]]*(claude|anthropic)|claude\.ai/code|claude\.com/claude-code|noreply@anthropic\.com'
EMOJI='🤖'
IDENT='(@agent\.local|^hq-[a-z0-9_.-]*@|^trinity-agent@|\[bot\]@|noreply@anthropic\.com)'
NAME_BAD='(claude|anthropic|\bagent\b|(^|[^a-z])hq-|trinity|codex|copilot|gemini|\bgpt|\bai\b|\bbot\b)'
fail=0
bad() { echo "::error::attribution-guard: $1"; fail=1; }
die() { echo "::error::attribution-guard: $1"; exit 2; }

scan() { # $1 label, stdin text
  local t
  t=$(cat)
  printf '%s\n' "$t" | grep -Eiq "$TRAILER" && bad "$1 has an Agent:/Requested-by:/Co-authored-by:/Claude-Session:/Generated-by: line"
  printf '%s\n' "$t" | grep -Eiq "$OTHER" && bad "$1 credits an AI (Generated with/by Claude, Signed-off-by Claude, claude.ai/code link, noreply@anthropic.com)"
  printf '%s\n' "$t" | grep -Fq "$EMOJI" && bad "$1 carries the robot emoji used as AI credit"
  return 0
}

[ "$EVENT" = pull_request ] || [ "$EVENT" = push ] || die "unknown EVENT '$EVENT'"
HEAD="${HEAD:-}"
[ -n "$HEAD" ] || die "HEAD sha is empty"
git rev-parse --verify -q "${HEAD}^{commit}" >/dev/null || die "head commit $HEAD is not in the checkout"

if [ "$EVENT" = pull_request ]; then
  scan "PR title" <<< "${TITLE:-}"
  scan "PR body" <<< "${BODY:-}"
fi

BASE="${BASE:-}"
if [ -z "$BASE" ] || [ "$BASE" = "$ZERO" ]; then
  [ "$EVENT" = push ] || die "base sha is empty on a pull request"
  echo "attribution-guard: no previous sha (new branch); judging the head commit only"
  commits=$(git rev-parse "$HEAD") || die "cannot resolve head"
else
  git rev-parse --verify -q "${BASE}^{commit}" >/dev/null || die "base commit $BASE is not in the checkout (unreachable); refusing to pass"
  commits=$(git rev-list "${BASE}..${HEAD}") || die "git rev-list ${BASE}..${HEAD} failed"
fi
[ -n "$commits" ] || die "no commits in ${BASE:-none}..${HEAD}: an empty range is an error, not a pass"

# dependabot PRs are exempt as PRs (hq-automerge squashes them as Jordan); every other change is judged per commit
dep=0
case "${PR_AUTHOR:-}" in dependabot*|renovate*) dep=1 ;; esac
case "${HEAD_REF:-}" in dependabot/*|renovate/*) dep=1 ;; esac

n=0
for c in $commits; do
  n=$((n+1))
  s=$(git log -1 --format=%h "$c") || die "git log failed for $c"
  msg=$(git log -1 --format=%B "$c") || die "git log failed for $c"
  an=$(git log -1 --format=%an "$c") || die "git log failed for $c"
  ae=$(git log -1 --format=%ae "$c") || die "git log failed for $c"
  cn=$(git log -1 --format=%cn "$c") || die "git log failed for $c"
  ce=$(git log -1 --format=%ce "$c") || die "git log failed for $c"
  scan "commit $s message" <<< "$msg"
  [ "$dep" = 0 ] || continue
  echo "$ae" | grep -Eiq "$IDENT" && bad "commit $s author is an agent/bot identity ($ae)"
  echo "$ce" | grep -Eiq "$IDENT" && bad "commit $s committer is an agent/bot identity ($ce)"
  echo "$an" | grep -Eiq "$NAME_BAD" && bad "commit $s author name looks like an agent or bot ($an)"
  echo "$cn" | grep -Eiq "$NAME_BAD" && bad "commit $s committer name looks like an agent or bot ($cn)"
  # Jordan's own PRs: every commit is authored and committed as him (name and email)
  if [ "$EVENT" = pull_request ] && [ "${PR_AUTHOR:-}" = "jordanallenlewis" ]; then
    echo "$ae" | grep -Eq "$JORDAN_RE" || bad "commit $s author email is not jordanallenlewis ($ae)"
    echo "$ce" | grep -Eq "$COMMITTER_OK_RE" || bad "commit $s committer email is not jordanallenlewis ($ce)"
    [ "$an" = "$JORDAN_NAME" ] || bad "commit $s author name is not '$JORDAN_NAME' ($an)"
    if [ "$ce" = noreply@github.com ]; then
      [ "$cn" = GitHub ] || bad "commit $s committer name is not GitHub for a noreply@github.com committer ($cn)"
    else
      [ "$cn" = "$JORDAN_NAME" ] || bad "commit $s committer name is not '$JORDAN_NAME' ($cn)"
    fi
  fi
  # direct pushes: the email must be Jordan's or GitHub's; the name is only screened (the fleet bot commits as "Jordan Lewis")
  if [ "$EVENT" = push ]; then
    echo "$ae" | grep -Eq "$JORDAN_RE" || bad "commit $s on a push: author email is not jordanallenlewis ($ae)"
    echo "$ce" | grep -Eq "$COMMITTER_OK_RE" || bad "commit $s on a push: committer email is not jordanallenlewis ($ce)"
  fi
done
[ "$fail" = 0 ] && echo "attribution-guard: clean ($n commits judged)"
exit "$fail"
