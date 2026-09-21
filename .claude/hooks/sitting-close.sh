#!/bin/bash
# Stop and SessionEnd hook: report what this session spent in its seat.
#
# A FIRED run (a Routine's firing) is one prompt, so its one Stop event
# is where the bill is known and the hook closes the sitting there
# (docs/spec-seat.md R-12.17). An INTERACTIVE sitting is a person's own
# session: it raises a Stop event on EVERY turn and waits in between, so
# the hook must not close and must not block there — it posts a TALLY
# (R-12.25), and the close comes from SessionEnd. The engine never
# estimates; both are the harness's own counts, reported.
#
# The mode is the SEAT's (R-10.8) and the session learns it from the
# answer to waymark_sit, which carries "mode" beside "sitting" — so this
# hook reads it out of the transcript rather than being told.
#
# Argument: "end" for the SessionEnd entry; anything else (the Stop
# entry passes nothing) is the Stop event.
#
# Two paths, as R-12.26 has them. When the environment carries the
# door's URL, the hook posts. When it carries nothing — a cloud
# environment that takes a repository and no settings — a FIRED session
# is held one time and given its counts to close by hand, and an
# INTERACTIVE one is told once that a tally needs the URL and left
# alone: a block on every turn would stop the person's work.
set -u

EVENT="${1:-stop}"

HOOK=$(cat)   # the hook's JSON, on stdin. Both paths read it.

# The program sums the transcript. Its argument is the path: "post"
# prints the door's body; "block" prints the answer to the harness, or
# nothing when the session must be left alone. BOTH print one status
# line first — "<mode>|<sitting>|<closed>" — so one walk of the
# transcript answers every question this script asks of it.
# NB: read, not $(cat <<PY). bash 3.2 quote-scans a heredoc that sits
# inside a command substitution, so one apostrophe in the Python below
# inverts every quote after it and the script stops parsing (the error
# lands far away, on the first ;; of a later case). No $( ), no scan.
read -r -d '' SUM <<'PY'
import glob, json, os, re, sys
FIELDS = ("input_tokens", "output_tokens",
          "cache_read_input_tokens", "cache_creation_input_tokens")
MODE = sys.argv[1] if len(sys.argv) > 1 else "post"
try:
    hook = json.loads(sys.stdin.read() or "{}")
except Exception:
    hook = {}
session, main = str(hook.get("session_id") or ""), str(hook.get("transcript_path") or "")
# A subagent's transcript sits beside the main one, with the same
# shape. Its tokens are the sitting's too.
paths = [main] if main else []
if main and session:
    paths += sorted(glob.glob(os.path.join(
        os.path.dirname(main), session, "subagents", "agent-*.jsonl")))

def text_of(block):  # a tool result is a string, or blocks of text
    body = block.get("content")
    if isinstance(body, list):
        return " ".join(p.get("text") or "" for p in body if isinstance(p, dict))
    return body if isinstance(body, str) else ""

totals, turns = dict.fromkeys(FIELDS, 0), 0
sat, sitting, seat_mode, closed = set(), "", "", False
for index, path in enumerate(paths):
    seen = set()
    try:
        handle = open(path, "r", errors="replace")
    except OSError:
        continue
    with handle:
        for line in handle:
            try:
                record = json.loads(line)
            except Exception:
                continue  # a partial or non-JSON line is not a bill
            if not isinstance(record, dict):
                continue
            content = (record.get("message") or {}).get("content")
            # The sit answers the sitting's id and the seat's mode. A
            # close in the main transcript means the bill is already in.
            for block in (content if index == 0 and isinstance(content, list) else []):
                if not isinstance(block, dict):
                    continue
                name, kind = str(block.get("name") or ""), block.get("type")
                if kind == "tool_use" and name.endswith("waymark_sit"):
                    sat.add(block.get("id"))
                elif kind == "tool_use" and name.endswith("waymark_invoke"):
                    arg = block.get("input") or {}
                    closed = closed or (arg.get("kind") == "sitting"
                                        and arg.get("action") == "close")
                elif kind == "tool_result" and block.get("tool_use_id") in sat:
                    answer = text_of(block)
                    named = re.findall(r'"sitting"\s*:\s*"([^"]+)"', answer)
                    if named:
                        sitting = named[-1]  # the last sit is the open one
                        # the mode rides in the same answer; a sit from
                        # before the field existed simply has none, and
                        # an absent mode reads as the fired one
                        modes = re.findall(r'"mode"\s*:\s*"([^"]+)"', answer)
                        seat_mode = modes[-1] if modes else ""
            if record.get("type") != "assistant":
                continue
            # One API response is several lines, one for each content
            # block, all with one requestId. Count it once.
            request = record.get("requestId") or record.get("uuid") or ""
            if request in seen:
                continue
            seen.add(request)
            usage = (record.get("message") or {}).get("usage") or {}
            for field in FIELDS:
                if isinstance(usage.get(field), int):
                    totals[field] += usage[field]
    if index == 0:
        turns = len(seen)

count = tuple(totals[field] for field in FIELDS)
# the status line, first and always: what the shell has to know about
# this session before it decides which door to knock on
sys.stdout.write("%s|%s|%d\n" % (seat_mode, sitting, 1 if closed else 0))
if MODE == "post":
    json.dump({"input_tokens": count[0], "output_tokens": count[1],
               "cache_read_tokens": count[2], "cache_write_tokens": count[3],
               "turns": turns, "harness_session": session,
               "note": ("Reported by the hook after %d turns." % turns)[:240]},
              sys.stdout)
    sys.exit(0)

# Say nothing unless a sitting is open, no close is in the transcript,
# and the harness is not already going on because this hook blocked.
if not sitting or closed or hook.get("stop_hook_active"):
    sys.exit(0)
json.dump({"decision": "block", "reason": (
    'Before you stop, close your sitting with its exact usage. Call '
    'waymark_invoke with kind "sitting", id "%s", action "close", and input '
    '{"input_tokens": %d, "output_tokens": %d, "cache_read_tokens": %d, '
    '"cache_write_tokens": %d, "turns": %d, "harness_session": "%s", "note": '
    '"<one sentence: what this wake moved, at most 240 characters>"}. Copy the '
    'numbers exactly as written; they are the harness\'s count, not yours. '
    'Then stop.') % (sitting, count[0], count[1], count[2], count[3],
                     turns, session)}, sys.stdout)
PY

# The tally door is the close's sibling, one word over. The variable
# names the CLOSE door (it always has), so the tally is derived: swap a
# trailing /close for /tally, and for a URL that does not end that way,
# append /tally and let the door say if it is wrong.
tally_url() {
  case "$1" in
    */close) printf '%s/tally' "${1%/close}" ;;
    *) printf '%s/tally' "$1" ;;
  esac
}

# One POST, and a door that refuses must never fail the session: say one
# line on stderr and go.
post_report() {
  # The key goes in a header, not a bearer: the identity layer reads a
  # bearer as an OIDC token. A stored credential adds the header
  # outside the container, so send the variable only when it is set.
  local url="$1" body="$2" reply status detail
  local key=()
  [ -n "${WAYMARK_SEAT_KEY:-}" ] && key=(-H "Waymark-Seat-Key: ${WAYMARK_SEAT_KEY}")
  reply=$(curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
    ${key[@]+"${key[@]}"} -d "$body" -w '\n%{http_code}' "$url" 2>&1)
  status=${reply##*$'\n'}
  case "$status" in
    2??) return 0 ;;
    [1-5][0-9][0-9])
      detail=$(printf '%s' "${reply%$'\n'*}" | python3 -c 'import json,sys
try: print(json.loads(sys.stdin.read()).get("detail") or "")
except Exception: pass' 2>/dev/null)
      echo "waymark: the sitting report was answered ${status}. ${detail}" >&2 ;;
    *) echo "waymark: the sitting report did not reach the door: $(printf '%s' \
         "$reply" | tr '\n' ' ')" >&2 ;;
  esac
  return 0
}

# Path one: the environment carries the door.
if [ -n "${WAYMARK_SEAT_URL:-}" ]; then
  OUT=$(printf '%s' "$HOOK" | python3 -c "$SUM" post 2>/dev/null) || {
    echo "waymark: the sitting hook could not read the transcript." >&2; exit 0; }
  STATUS_LINE=${OUT%%$'\n'*}
  # the payload is whatever follows the status line — and nothing at
  # all when the program printed the status line alone
  case "$OUT" in
    *$'\n'*) BODY=${OUT#*$'\n'} ;;
    *) BODY="" ;;
  esac
  MODE=${STATUS_LINE%%|*}
  REST=${STATUS_LINE#*|}
  SITTING=${REST%%|*}
  CLOSED=${REST##*|}
  [ -n "$BODY" ] || exit 0

  if [ "$EVENT" = "end" ]; then
    # SessionEnd closes what the turns tallied (R-12.25). Only an
    # interactive sitting: a fired run's Stop already posted its close,
    # and a second close here would be answered 409 — or, worse, paired
    # with another run's open sitting, since this run's is gone.
    [ "$MODE" = "interactive" ] || exit 0
    [ -n "$SITTING" ] || exit 0
    [ "$CLOSED" = "0" ] || exit 0
    post_report "$WAYMARK_SEAT_URL" "$BODY"
    exit 0
  fi

  if [ "$MODE" = "interactive" ]; then
    # Every turn, never blocking: the counts so far, onto a sitting that
    # stays open. Cumulative, so a replay writes what is already there.
    post_report "$(tally_url "$WAYMARK_SEAT_URL")" "$BODY"
    exit 0
  fi

  # A fired run (or a session that never sat, or one that sat before the
  # mode existed): today's behavior, unchanged.
  post_report "$WAYMARK_SEAT_URL" "$BODY"
  exit 0
fi

# Path two: no door in the environment.
[ "$EVENT" = "end" ] && exit 0   # nothing to post, and SessionEnd cannot block

ANSWER=$(printf '%s' "$HOOK" | python3 -c "$SUM" block 2>/dev/null) || {
  echo "waymark: the sitting hook could not read the transcript." >&2; exit 0; }
STATUS_LINE=${ANSWER%%$'\n'*}
case "$ANSWER" in
  *$'\n'*) REPLY=${ANSWER#*$'\n'} ;;
  # the status line alone: this session is not to be held, and stdout
  # must stay empty — the harness reads it as the hook's decision
  *) REPLY="" ;;
esac
MODE=${STATUS_LINE%%|*}
REST=${STATUS_LINE#*|}
SITTING=${REST%%|*}

# An interactive sitting is never blocked and never closed by hand: the
# person is still working. Say once what the environment is missing —
# once per sitting, by a marker beside the temporary files — and let the
# sweep close it after the seat's sitting_idle_seconds.
if [ "$MODE" = "interactive" ]; then
  if [ -n "$SITTING" ]; then
    MARK="${TMPDIR:-/tmp}/waymark-tally-note-${SITTING//[^A-Za-z0-9_-]/_}"
    if [ ! -e "$MARK" ]; then
      : > "$MARK" 2>/dev/null || true
      echo "waymark: an interactive sitting tallies through WAYMARK_SEAT_URL; none is set, the sweep closes it." >&2
    fi
  fi
  exit 0
fi

# Hold the stop one time and hand the session the id and the counts. A
# session that never sat gets nothing: the hook rides in every waymark
# cloud session.
[ -n "$REPLY" ] && printf '%s\n' "$REPLY"
exit 0
