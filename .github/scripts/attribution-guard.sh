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
# Pushed dependabot/renovate merges (GitHub web squash): bot author, committer noreply@github.com, and GitHub's own co-author line for the bot.
BOT_AUTHOR_RE='^(49699333\+dependabot\[bot\]|29139614\+renovate\[bot\])@users\.noreply\.github\.com$'
BOT_COAUTHOR_RE='^Co-authored-by: (dependabot\[bot\] <49699333\+dependabot\[bot\]@users\.noreply\.github\.com>|renovate\[bot\] <29139614\+renovate\[bot\]@users\.noreply\.github\.com>)$'
IDENT='(@agent\.local|^hq-[a-z0-9_.-]*@|^trinity-agent@|\[bot\]@|noreply@anthropic\.com)'
NAME_BAD='(claude|anthropic|\bagent\b|(^|[^a-z])hq-|trinity|codex|copilot|gemini|\bgpt|\bai\b|\bbot\b)'
fail=0
bad() { echo "::error::attribution-guard: $1"; fail=1; }
die() { echo "::error::attribution-guard: $1"; exit 2; }

# Greps read a here-string, never a pipe: under pipefail a pipe into grep -q can die of SIGPIPE on large text and skip the match.
scan() { # $1 label, stdin text
  local t
  t=$(cat)
  grep -Eiq "$TRAILER" <<< "$t" && bad "$1 has an Agent:/Requested-by:/Co-authored-by:/Claude-Session:/Generated-by: line"
  grep -Eiq "$OTHER" <<< "$t" && bad "$1 credits an AI (Generated with/by Claude, Signed-off-by Claude, claude.ai/code link, noreply@anthropic.com)"
  grep -Fq "$EMOJI" <<< "$t" && bad "$1 carries the robot emoji used as AI credit"
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
  scanmsg=$msg
  botmerge=0
  if [ "$EVENT" = push ]; then
    # drop only GitHub's exact co-author line for the bot addresses; any other co-author line stays and fails
    scanmsg=$(grep -Ev "$BOT_COAUTHOR_RE" <<< "$msg"; true)
    if grep -Eq "$BOT_AUTHOR_RE" <<< "$ae" && [ "$ce" = noreply@github.com ]; then botmerge=1; fi
  fi
  scan "commit $s message" <<< "$scanmsg"
  # a bot merge on a push (exact bot author email, committer noreply@github.com) skips the identity checks below
  [ "$botmerge" = 0 ] || continue
  [ "$dep" = 0 ] || continue
  grep -Eiq "$IDENT" <<< "$ae" && bad "commit $s author is an agent/bot identity ($ae)"
  grep -Eiq "$IDENT" <<< "$ce" && bad "commit $s committer is an agent/bot identity ($ce)"
  grep -Eiq "$NAME_BAD" <<< "$an" && bad "commit $s author name looks like an agent or bot ($an)"
  grep -Eiq "$NAME_BAD" <<< "$cn" && bad "commit $s committer name looks like an agent or bot ($cn)"
  # Jordan's own PRs: every commit is authored and committed as him (name and email)
  if [ "$EVENT" = pull_request ] && [ "${PR_AUTHOR:-}" = "jordanallenlewis" ]; then
    grep -Eq "$JORDAN_RE" <<< "$ae" || bad "commit $s author email is not jordanallenlewis ($ae)"
    grep -Eq "$COMMITTER_OK_RE" <<< "$ce" || bad "commit $s committer email is not jordanallenlewis ($ce)"
    [ "$an" = "$JORDAN_NAME" ] || bad "commit $s author name is not '$JORDAN_NAME' ($an)"
    if [ "$ce" = noreply@github.com ]; then
      [ "$cn" = GitHub ] || bad "commit $s committer name is not GitHub for a noreply@github.com committer ($cn)"
    else
      [ "$cn" = "$JORDAN_NAME" ] || bad "commit $s committer name is not '$JORDAN_NAME' ($cn)"
    fi
  fi
  # direct pushes: the email must be Jordan's or GitHub's; the name is only screened (the fleet bot commits as "Jordan Lewis")
  if [ "$EVENT" = push ]; then
    grep -Eq "$JORDAN_RE" <<< "$ae" || bad "commit $s on a push: author email is not jordanallenlewis ($ae)"
    grep -Eq "$COMMITTER_OK_RE" <<< "$ce" || bad "commit $s on a push: committer email is not jordanallenlewis ($ce)"
  fi
done
[ "$fail" = 0 ] && echo "attribution-guard: clean ($n commits judged)"
exit "$fail"
