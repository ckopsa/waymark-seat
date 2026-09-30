#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Stop, SubagentStop and SessionEnd hook: report what this session spent
# in its seat. A run that ends a turn while an agent it launched in the
# background is still out is not done: that Stop, and every SubagentStop,
# reports "waiting" and neither closes nor holds. Only the last Stop,
# with nothing pending, closes the sitting with the whole run's counts.
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
# Argument: "end" for the SessionEnd entry; "close-run" for a close
# from outside the run (see below: localfire calls it); anything else
# (the Stop entry passes nothing) is the Stop event.
#
# Two paths, as R-12.26 has them. When the environment carries the
# door's URL, the hook posts. When it carries nothing — a cloud
# environment that takes a repository and no settings — a FIRED session
# closes its sitting with the transcript key its sit answered, and is
# held one time and given its counts to close by hand only when that
# close is refused. An
# INTERACTIVE one is told once that a tally needs the URL and left
# alone: a block on every turn would stop the person's work.
set -u

EVENT="${1:-stop}"

HOOK=$(cat)   # the hook's JSON, on stdin. Both paths read it.

# THE TRANSCRIPT GOES FIRST (docs/spec-transcript.md § 6). The sit
# answers an address and a key for this sitting's transcript, beside the
# sitting's id; the program below finds the last such answer, redacts
# every line, and appends what the engine does not hold yet, chained.
# It runs on every Stop and on SessionEnd, the second Stop of a fired
# run included: that one comes after the close, and it carries the last
# lines. It prints nothing on stdout (the harness reads stdout as the
# hook's decision), it spends at most 20 seconds, and nothing it meets
# fails the session: a refusal or a dark network is one line on stderr,
# and the close below runs as it always did.
read -r -d '' UPLOAD <<'PY'
import glob, gzip, hashlib, json, os, re, subprocess, sys, tempfile, time

START = time.time()
BUDGET = 20.0
POST_BYTES = 2 * 1024 * 1024   # under the door's 4 MiB, JSON escaping included
ZERO = "0" * 64

def say(msg):
    sys.stderr.write("waymark: the transcript upload " + msg + "\n")

try:
    hook = json.loads(sys.stdin.read() or "{}")
except Exception:
    hook = {}
session = str(hook.get("session_id") or "")
main = str(hook.get("transcript_path") or "")
if not main or not os.path.isfile(main):
    sys.exit(0)

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as h:
            text = h.read()
    except OSError:
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines

def text_of(block):
    body = block.get("content")
    if isinstance(body, list):
        return " ".join(p.get("text") or "" for p in body if isinstance(p, dict))
    return body if isinstance(body, str) else ""

main_lines = read_lines(main)

# The sit answers {"sitting": …, "transcript": {"url": …, "key": …}}.
# The LAST such answer is the live one: a second sit mints a new key.
sat, found, seat_keys, transcript_keys = set(), None, set(), set()
for line in main_lines:
    try:
        rec = json.loads(line)
    except Exception:
        continue
    content = (rec.get("message") or {}).get("content") if isinstance(rec, dict) else None
    if not isinstance(content, list):
        continue
    for block in content:
        if not isinstance(block, dict):
            continue
        name, kind = str(block.get("name") or ""), block.get("type")
        if kind == "tool_use" and name.endswith("waymark_sit"):
            sat.add(block.get("id"))
            key = (block.get("input") or {}).get("key")
            if isinstance(key, str) and key:
                seat_keys.add(key)
        elif kind == "tool_result" and block.get("tool_use_id") in sat:
            try:
                answer = json.loads(text_of(block))
            except Exception:
                continue
            t = answer.get("transcript") if isinstance(answer, dict) else None
            if isinstance(t, dict) and t.get("url") and t.get("key"):
                transcript_keys.add(str(t["key"]))
                found = (str(t["url"]), str(t["key"]), str(answer.get("sitting") or ""))
if not found:
    sys.exit(0)
url, key, sitting = found

# ── what is redacted (R-7.1) ─────────────────────────────────────────
fire_keys = set()
for line in main_lines:
    for m in re.finditer(r"Key:\s*([A-Za-z0-9_-]{16,})", line):
        fire_keys.add(m.group(1))
env_values = set()
for name, value in os.environ.items():
    if (name.endswith(("KEY", "TOKEN", "SECRET", "PASSWORD")) or name == "WAYMARK_SEAT_URL") \
            and isinstance(value, str) and len(value) >= 8:
        env_values.add(value)
secrets = []   # (text as it appears inside a JSON string, class)
for cls, values in (("seat-key", seat_keys), ("fire-key", fire_keys),
                    ("transcript-key", transcript_keys), ("env", env_values)):
    for v in values:
        secrets.append((json.dumps(v)[1:-1], cls))
secrets.sort(key=lambda s: -len(s[0]))
PATTERNS = [re.compile(p) for p in (
    r"gh[pos]_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
    r"sk-ant-[A-Za-z0-9_-]{16,}", r"xox[bp]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}", r"Bearer [A-Za-z0-9._~+/=-]{16,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")]

def redact(line, counts):
    # plain replacement inside the raw line: a secret is replaced where
    # it stands, the line stays valid JSON, and a line with nothing to
    # redact keeps its exact bytes, so its chain is the same every time
    for text, cls in secrets:
        n = line.count(text)
        if n:
            line = line.replace(text, "[redacted:" + cls + "]")
            counts[cls] = counts.get(cls, 0) + n
    for pat in PATTERNS:
        line, n = pat.subn("[redacted:pattern]", line)
        if n:
            counts["pattern"] = counts.get("pattern", 0) + n
    return line

files = [("main", main)]
if session:
    for path in sorted(glob.glob(os.path.join(os.path.dirname(main), session,
                                              "subagents", "agent-*.jsonl"))):
        stem = os.path.basename(path)[len("agent-"):-len(".jsonl")]
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", stem):
            files.append(("agent-" + stem, path))

state_path = os.path.join(tempfile.gettempdir(),
                          "waymark-transcript-" + re.sub(r"[^A-Za-z0-9_-]", "_", sitting or key[:8]) + ".json")
try:
    with open(state_path) as h:
        held = json.load(h)
except Exception:
    held = {}

def post(body):
    left = BUDGET - (time.time() - START)
    if left < 2:
        return None, None
    fd, tmp = tempfile.mkstemp(suffix=".json.gz")
    try:
        with os.fdopen(fd, "wb") as h:
            h.write(gzip.compress(json.dumps(body).encode("utf-8")))
        out = subprocess.run(
            ["curl", "-sS", "--max-time", str(int(min(left, 15))), "-X", "POST",
             "-H", "Content-Type: application/json", "-H", "Content-Encoding: gzip",
             "-H", "Waymark-Transcript-Key: " + key,
             "--data-binary", "@" + tmp, "-w", "\n%{http_code}", url],
            capture_output=True, text=True)
    finally:
        os.unlink(tmp)
    text = out.stdout or ""
    code = text.rsplit("\n", 1)[-1] if "\n" in text else ""
    try:
        doc = json.loads(text.rsplit("\n", 1)[0]) if "\n" in text else {}
    except Exception:
        doc = {}
    if not code.isdigit():
        say("did not reach the door: " + (out.stderr or "no answer").strip().replace("\n", " "))
        return None, None
    return int(code), doc

run_session = os.environ.get("CLAUDE_CODE_REMOTE_SESSION_ID") or None
stopped = False
for name, path in files:
    if stopped:
        break
    per_line = []
    lines = []
    for l in read_lines(path):
        c = {}
        lines.append(redact(l, c))
        per_line.append(c)
    chains = []
    prior = ZERO
    for l in lines:
        prior = hashlib.sha256((prior + "\n" + l).encode("utf-8")).hexdigest()
        chains.append(prior)
    start = int(held.get(name, 0))
    retried = False
    while start < len(lines):
        batch, size = [], 0
        for l in lines[start:]:
            n = len(l.encode("utf-8")) + 64
            if batch and size + n > POST_BYTES:
                break
            batch.append(l)
            size += n
        counts = {}
        for c in per_line[start:start + len(batch)]:
            for cls, n in c.items():
                counts[cls] = counts.get(cls, 0) + n
        body = {"file": name, "from": start,
                "prior": chains[start - 1] if start else ZERO,
                "lines": batch,
                "redactions": counts}
        if session:
            body["harness_session"] = session[:128]
        if run_session:
            body["run_session"] = run_session[:128]
        code, doc = post(body)
        if code is None:
            stopped = True
            break
        if code == 200:
            start = int(doc.get("held", start + len(batch)))
            held[name] = start
            continue
        if code == 409 and isinstance(doc.get("held"), int) and doc.get("title") == "Lines missing" \
                and not retried:
            retried = True
            start = min(int(doc["held"]), len(lines))
            continue
        say("was answered %d for %s: %s" % (code, name, doc.get("detail") or doc.get("title") or ""))
        if code in (404, 413) or (code == 409 and doc.get("title") == "Sealed"):
            stopped = True
        break
try:
    with open(state_path, "w") as h:
        json.dump(held, h)
except Exception:
    pass
PY
printf '%s' "$HOOK" | python3 -c "$UPLOAD" >/dev/null || true

# The program sums the transcript. Its argument is the path: "post"
# prints the door's body; "block" prints the answer to the harness, or
# nothing when the session must be left alone. BOTH print one status
# line first — "<mode>|<sitting>|<closed>|<waiting>" — so one walk of the
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
sat, sitting, seat_mode, closed, transcript = set(), "", "", False, None
# Agent launches by tool_use id (True when run in the background), the
# tool_use ids of background Bash and Monitor launches, and the ids of
# the background agents and tasks that have not handed back yet.
launched, tasks, pending = {}, set(), set()
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
            # A later line that names a pending agent is its hand-back
            # (the task notification). The launch's own answer names it
            # too, but it is only added below, after this check.
            if index == 0 and pending and record.get("type") != "assistant":
                pending -= {agent for agent in pending if agent in line}
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
                elif kind == "tool_use" and name in ("Agent", "Task"):
                    launched[block.get("id")] = bool(
                        (block.get("input") or {}).get("run_in_background"))
                elif kind == "tool_use" and (name == "Monitor" or (
                        name == "Bash" and (block.get("input") or {}).get("run_in_background"))):
                    tasks.add(block.get("id"))
                elif kind == "tool_use" and name == "TaskStop":
                    # a stopped task will not hand back: drop the id it names
                    arg = block.get("input") or {}
                    pending -= {v for v in arg.values() if isinstance(v, str)}
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
                        # and the transcript's address and key, which
                        # also close this sitting (R-12.17)
                        try:
                            t = json.loads(answer).get("transcript")
                        except Exception:
                            t = None
                        transcript = ((str(t["url"]), str(t["key"]))
                                      if isinstance(t, dict) and t.get("url") and t.get("key")
                                      else None)
                elif kind == "tool_result" and block.get("tool_use_id") in launched:
                    answer = text_of(block)
                    if launched[block.get("tool_use_id")] or re.search(
                            r"async.*launched|launched.*background", answer, re.I | re.S):
                        pending.update(re.findall(r"agentId:\s*([\w-]+)", answer))
                elif kind == "tool_result" and block.get("tool_use_id") in tasks:
                    # "Command running in background with ID: <id>.", and the
                    # Monitor's answer names its task id likewise; the hand-back
                    # is a later <task-notification> line naming <task-id><id>
                    pending.update(re.findall(
                        r"(?:\bID|\btask[ _-]?id)[\"'\s:=]+([\w-]+)", text_of(block), re.I))
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
# a run still waiting on a background agent it launched, or a subagent's
# own stop, is not the run's last Stop
waiting = bool(pending) or hook.get("hook_event_name") == "SubagentStop"
sys.stdout.write("%s|%s|%d|%d\n" % (seat_mode, sitting, 1 if closed else 0,
                                   1 if waiting else 0))
report = {"input_tokens": count[0], "output_tokens": count[1],
          "cache_read_tokens": count[2], "cache_write_tokens": count[3],
          "turns": turns, "harness_session": session[:128],
          "note": ("Reported by the hook after %d turns." % turns)[:240]}
if MODE == "post":
    json.dump(report, sys.stdout)
    sys.exit(0)

# "close-run": what "direct" answers, for a close from OUTSIDE the run.
# No stop is being held and the run is gone, so neither a pending agent
# nor stop_hook_active holds it back, and the caller note (from
# WAYMARK_CLOSE_NOTE) stands in for the hook note when one is given.
if MODE == "close-run":
    note = os.environ.get("WAYMARK_CLOSE_NOTE", "").strip()
    if note:
        report["note"] = note[:240]
    if sitting and not closed and transcript \
            and re.search(r"/transcript/?$", transcript[0]):
        sys.stdout.write(re.sub(r"/transcript/?$", "/close", transcript[0]) + "\n")
        sys.stdout.write(transcript[1] + "\n")
        json.dump(report, sys.stdout)
    sys.exit(0)

# While waiting, the status line alone: no close, and no hold.
if waiting:
    sys.exit(0)

# "direct": the close door, the transcript key and the body, one line
# each, when this sitting is open and the sit answered a transcript
# whose address ends in /transcript; the status line alone otherwise.
if MODE == "direct":
    if sitting and not closed and not hook.get("stop_hook_active") \
            and transcript and re.search(r"/transcript/?$", transcript[0]):
        sys.stdout.write(re.sub(r"/transcript/?$", "/close", transcript[0]) + "\n")
        sys.stdout.write(transcript[1] + "\n")
        json.dump(report, sys.stdout)
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
      echo "waymark: the sitting report for ${SITTING:-no sitting} was answered ${status}. ${detail}" >&2 ;;
    *) echo "waymark: the sitting report for ${SITTING:-no sitting} did not reach the door: $(printf '%s' \
         "$reply" | tr '\n' ' ')" >&2 ;;
  esac
  return 0
}

# An EXTERNAL close for a fired run: localfire calls it for a run it
# marks lost or whose process exited, when no Stop will come to close
# the sitting. `sitting-close.sh close-run [note]`, with the run's
# {session_id, transcript_path} on stdin and the note as the argument or
# in WAYMARK_CLOSE_NOTE. It finds the sitting and the transcript key as
# direct_close does and posts the close with the harness's counts and
# that note, whether or not the environment carries the door. It prints
# ONE status line on stdout, for the caller: "closed <sitting>",
# "already-closed <sitting>" (a close in the transcript, or a 409), or
# "failed <sitting>: <reason>"; and it exits 0 only when the sitting is
# closed, so a failure is the caller's to say.
if [ "$EVENT" = "close-run" ]; then
  OUT=$(printf '%s' "$HOOK" | WAYMARK_CLOSE_NOTE="${2:-${WAYMARK_CLOSE_NOTE:-}}" \
    python3 -c "$SUM" close-run 2>/dev/null) || {
    echo "failed (none): the transcript could not be read"; exit 1; }
  STATUS_LINE=${OUT%%$'\n'*}
  REST=${STATUS_LINE#*|}
  SITTING=${REST%%|*}
  REST=${REST#*|}
  CLOSED=${REST%%|*}
  [ -n "$SITTING" ] || { echo "failed (none): the transcript holds no sit"; exit 1; }
  [ "$CLOSED" = "0" ] || { echo "already-closed $SITTING"; exit 0; }
  case "$OUT" in
    *$'\n'*$'\n'*$'\n'*) OUT=${OUT#*$'\n'} ;;
    *) echo "failed $SITTING: the sit answered no transcript address and key"; exit 1 ;;
  esac
  URL=${OUT%%$'\n'*}
  REST=${OUT#*$'\n'}
  KEY=${REST%%$'\n'*}
  BODY=${REST#*$'\n'}
  if [ -z "$URL" ] || [ -z "$KEY" ] || [ -z "$BODY" ]; then
    echo "failed $SITTING: the close door, the transcript key or the counts came back empty"; exit 1
  fi
  REPLY=$(curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
    -H "Waymark-Transcript-Key: ${KEY}" -d "$BODY" -w '\n%{http_code}' "$URL" 2>&1)
  STATUS=${REPLY##*$'\n'}
  case "$STATUS" in
    2??) echo "closed $SITTING"; exit 0 ;;
    409) echo "already-closed $SITTING"; exit 0 ;;
    [1-5][0-9][0-9])
      echo "failed $SITTING: the door answered ${STATUS}: $(printf '%s' "${REPLY%$'\n'*}" | tr '\n' ' ' | cut -c1-200)" ;;
    *) echo "failed $SITTING: it did not reach the door: $(printf '%s' "$REPLY" | tr '\n' ' ' | cut -c1-200)" ;;
  esac
  exit 1
fi

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
  REST=${REST#*|}
  CLOSED=${REST%%|*}
  WAITING=${REST#*|}
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

  # A fired run still waiting on an agent it launched is not done: tally
  # what it has spent so far, and leave the close to its last Stop.
  if [ "$WAITING" = "1" ]; then
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

# A fired run closes its own sitting (R-12.17): the sit answered the
# transcript's address and key, the key also opens the close beside it,
# and the transcript went up above. A 2xx means the bill is in and the
# stop is not held; anything else falls back to the hold below, once.
# Every way the close can miss says so on stderr, one line naming the
# sitting and the reason, so the next miss can be read off the hook log.
miss() {
  echo "waymark: the close of sitting ${SITTING:-(none)} did not land: $1; holding the stop." >&2
}
direct_close() {
  local out url rest key body reply status
  out=$(printf '%s' "$HOOK" | python3 -c "$SUM" direct 2>/dev/null) || {
    miss "the hook could not read the transcript"; return 1; }
  case "$out" in
    *$'\n'*$'\n'*$'\n'*) out=${out#*$'\n'} ;;
    *) miss "the sit answered no transcript address and key"; return 1 ;;
  esac
  url=${out%%$'\n'*}
  rest=${out#*$'\n'}
  key=${rest%%$'\n'*}
  body=${rest#*$'\n'}
  if [ -z "$url" ] || [ -z "$key" ] || [ -z "$body" ]; then
    miss "the close door, the transcript key or the counts came back empty"; return 1
  fi
  reply=$(curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
    -H "Waymark-Transcript-Key: ${key}" -d "$body" -w '\n%{http_code}' "$url" 2>&1)
  status=${reply##*$'\n'}
  case "$status" in
    2??) return 0 ;;
    [1-5][0-9][0-9])
      miss "the door answered ${status}: $(printf '%s' "${reply%$'\n'*}" | tr '\n' ' ' | cut -c1-200)" ;;
    *) miss "it did not reach the door: $(printf '%s' "$reply" | tr '\n' ' ' | cut -c1-200)" ;;
  esac
  return 1
}

# Hold the stop one time and hand the session the id and the counts. A
# session that never sat gets nothing: the hook rides in every waymark
# cloud session.
if [ -n "$REPLY" ]; then
  direct_close && exit 0
  printf '%s\n' "$REPLY"
fi
exit 0
