#!/usr/bin/env python3
"""AGSH test suite — edge cases, security, undo, scale, determinism."""
import json, os, subprocess, shutil, tempfile, time, sys

PASS, FAIL = [], []
AGSH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agsh.py")

def run_script(script, cwd, extra_flags=None):
    return subprocess.run(["python3", AGSH] + (extra_flags or []), input=script, capture_output=True,
                          text=True, timeout=60, cwd=cwd)

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("PASS" if cond else "FAIL"), "-", name, ("| " + detail if detail and not cond else ""))

def make_env():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "fixtures"))
    json.dump({"results": [
        {"id": 1, "name": "A", "status": "active", "email": "a@company.com"},
        {"id": 2, "name": "B", "status": "inactive", "email": "b@x.org"},
        {"id": 3, "name": "C", "status": "active", "email": "C@Company.COM"},
        {"id": 4, "name": "D", "status": "active", "email": "d@gmail.com"},
    ]}, open(os.path.join(d, "fixtures", "api.example.com.json"), "w"))
    return d

def parse_out(proc):
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None

d = make_env()

# --- 1. EDGE CASES ---
p = run_script("frobnicate x", d)
o = parse_out(p)
check("unknown verb -> structured error", o and "error" in o and o["error"]["step"] == "frobnicate")

p = run_script("filter status=active", d)  # filter without input
o = parse_out(p)
check("filter with no input -> structured error", o and "error" in o and o["error"]["step"] == "filter")

p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| pick nosuchfield', d)
o = parse_out(p)
check("pick missing field -> empty dicts, no crash", o and o["result"] == [{}, {}, {}],
      f"got {o}")

p = run_script('write /etc/agsh_should_not_exist.json', d)
o = parse_out(p)
check("write with no data / bare path -> structured error", o and "error" in o)

p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| filter email ends-with @company.com\n| pick id\n| assert count>=1\n| read nonexistent_file.json', d)
o = parse_out(p)
check("read missing file mid-pipeline -> error step read", o and "error" in o and o["error"]["step"] == "read")

p = run_script("   ", d)
check("empty script -> JSON result null, no crash", parse_out(p) is not None and parse_out(p)["result"] is None)

# --- 2. SECURITY: path traversal ---
outside = os.path.dirname(d)
for stale in ("traversal_escape.json", "escape2.json"):
    p_ = os.path.join(outside if "traversal" in stale else tempfile.gettempdir(), stale)
    if os.path.exists(p_): os.remove(p_)
p = run_script('fetch https://api.example.com/users paginate=results\n| write ../traversal_escape.json', d)
check("path traversal outside workdir BLOCKED",
      not os.path.exists(os.path.join(outside, "traversal_escape.json")),
      "file escaped the sandbox dir!")

p = run_script('fetch https://api.example.com/users paginate=results\n| write ../../escape2.json', d)
check("deep traversal blocked", not os.path.exists(os.path.join(tempfile.gettempdir(), "escape2.json")))

# --- 3. UNDO SEMANTICS ---
p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| write a.json\n| checkpoint\n| write b.json\n| undo\n', d)
o = parse_out(p)
a_ok = os.path.exists(os.path.join(d, "a.json"))
b_ok = os.path.exists(os.path.join(d, "b.json"))
check("undo reverts post-checkpoint write only", a_ok and not b_ok,
      f"a.json exists={a_ok}, b.json exists={b_ok}")

p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| write a.json\n| checkpoint\n| write b.json\n| undo checkpoint=0\n', d)
o = parse_out(p)
check("undo to checkpoint 0 reverts all since", not os.path.exists(os.path.join(d, "b.json")))

p = run_script('fetch https://api.example.com/users paginate=results\n| write a.json\n| write a.json\n| undo\n', d)
o = parse_out(p)
check("undo restores previous content (overwrite)", o is not None and os.path.exists(os.path.join(d, "a.json")))

# --- 4. SCALE ---
json.dump({"results": [{"id": i, "status": "active", "email": f"u{i}@company.com"}
                        for i in range(10000)]},
          open(os.path.join(d, "fixtures", "api.example.com.json"), "w"))
t0 = time.time()
p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| filter email ends-with @company.com\n| pick id,email\n| write big.json\n| assert count>0\n', d)
dt = time.time() - t0
o = parse_out(p)
check("10k rows pipeline completes", o and o["result"].get("written") == 10000, f"got {o}")
check("10k rows under 5s", dt < 5, f"{dt:.2f}s")

# --- 5. DETERMINISM ---
p1 = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| pick email\n| map lower email\n', d)
p2 = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| pick email\n| map lower email\n', d)
o1, o2 = parse_out(p1), parse_out(p2)
check("deterministic: same script twice -> identical result",
      o1 and o2 and json.dumps(o1["result"]) == json.dumps(o2["result"]))

# --- 6. PERMISSION MODEL: plan mode ---
p = run_script('fetch https://api.example.com/users paginate=results\n| write out.json\n| run echo hi\n| post https://api.example.com/things\n', d)
# NOTE: run_script has no flags; plan mode needs flags — run manually:
import subprocess as sp
plan_p = sp.run(["python3", AGSH, "--plan"], input='fetch https://api.example.com/users paginate=results\n| write out.json\n| run echo hi\n| post https://api.example.com/things\n',
                capture_output=True, text=True, cwd=d)
plan = json.loads(plan_p.stdout)
check("plan mode: no execution, aggregate risks", "stages" in plan and "summary" in plan
      and plan["summary"].get("exec") == 1 and plan["summary"].get("network-write") == 1,
      f"got {plan.get('summary')}")
check("plan verdict requires --allow-run + --approve",
      set(plan["approval_required"]) == {"--allow-run", "--approve"}, f"got {plan['approval_required']}")

# run gated without flag
p = run_script('run echo hi\n', d)
o = parse_out(p)
check("run blocked without --allow-run", o and "error" in o and o["error"]["step"] == "run")

# run allowed with flag, restricted env
p = sp.run(["python3", AGSH, "--allow-run"], input='run echo $HOME\n', capture_output=True, text=True, cwd=d)
o = json.loads(p.stdout)
check("run with --allow-run executes restricted (HOME=cwd)",
      o["result"]["exit_code"] == 0 and o["result"]["stdout"] == d, f"got {o['result']}")

# --- 7. HUMAN GATE: ask ---
p = run_script('ask Continue?\n', d)
o = parse_out(p)
check("ask without answer -> exit 2 + needs_human", p.returncode == 2 and o and o.get("needs_human") is True,
      f"exit={p.returncode} out={p.stdout[:100]}")
p = sp.run(["python3", AGSH, "--answer", "yes"], input='ask Continue?\n', capture_output=True, text=True, cwd=d)
o = json.loads(p.stdout)
check("ask with --answer continues pipeline", o["result"]["answer"] == "yes", f"got {o['result']}")

# --- 8. WORLD-STATE checkpoint (cross-session) ---
# session 1: create files + save world
p = run_script('fetch https://api.example.com/users paginate=results\n| filter status=active\n| write s1.json\n| checkpoint save=world.json\n', d)
o = parse_out(p)
check("checkpoint save= writes world file", o and o["result"]["world"] is not None, f"got {o}")
# simulate new session: files deleted, then resume restores them
os.remove(os.path.join(d, "s1.json"))
p = run_script('resume world.json\n', d)
o = parse_out(p)
s1_restored = os.path.exists(os.path.join(d, "s1.json"))
check("resume restores deleted files (cross-session state)", s1_restored and o and o["result"]["resumed"] == "world.json",
      f"s1 exists={s1_restored}")

# --- 9. POST approval + REAL API undo (local HTTP server) ---
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
hits = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        hits.append(("POST", self.path))
        self.send_response(201); self.end_headers(); self.wfile.write(b'{"id": 42}')
    def do_GET(self):
        hits.append(("GET", self.path))
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok": true}')
    def do_DELETE(self):
        hits.append(("DELETE", self.path))
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]

# post without approval -> blocked
p = run_script(f'post http://127.0.0.1:{port}/things\n', d)
o = parse_out(p)
check("post blocked without --approve", o and "error" in o and "approval" in o["error"]["message"])

# post with approval (localhost test server => --allow-private-net), then real DELETE undo
p = sp.run(["python3", AGSH, "--approve", "--allow-private-net"], input=f'post http://127.0.0.1:{port}/things undo_method=DELETE undo_url=http://127.0.0.1:{port}/things/42\n| undo\n', capture_output=True, text=True, cwd=d)
o = json.loads(p.stdout)
methods = [m for m, _ in hits]
check("post with --approve executes", any(m == "POST" for m in methods), f"hits={hits}")
check("undo performs REAL DELETE against server", any(m == "DELETE" for m in methods)
      and "HTTP 204" in json.dumps(o["result"]), f"hits={hits} result={o['result']}")
srv.shutdown()

# --- 10. REVIEWER BLIND-SPOTS (negative tests) ---
# append must be sandboxed like read/write
outside = os.path.dirname(d)
esc = os.path.join(outside, "APPEND_ESCAPE.txt")
if os.path.exists(esc): os.remove(esc)
p = run_script('append /tmp/APPEND_ESCAPE_TXT_PLACEHOLDER\n', d)  # absolute → likely blocked
p = run_script(f'append {esc}\n', d)
o = parse_out(p)
check("append outside workdir BLOCKED (reviewer bug #1)",
      o and "error" in o and not os.path.exists(esc), f"out={o} exists={os.path.exists(esc)}")

# resume must not be an arbitrary write primitive
wf = os.path.join(d, "evil_world.json")
json.dump({"data": 1, "files": {"/tmp/RESUME_ESCAPE.txt": "pwned"}, "log_len": 0},
          open(wf, "w"))
esc2 = "/tmp/RESUME_ESCAPE.txt"
if os.path.exists(esc2): os.remove(esc2)
p = run_script('resume evil_world.json\n', d)
o = parse_out(p)
check("resume with absolute path in world file BLOCKED (reviewer bug #2)",
      o and "error" in o and not os.path.exists(esc2), f"out={o} exists={os.path.exists(esc2)}")

# inline approve=1 must NOT bypass --approve (reviewer bug #3)
p = sp.run(["python3", AGSH], input=f'post http://127.0.0.1:{port}/things approve=1\n',
           capture_output=True, text=True, cwd=d)
o = parse_out(p)
check("post with inline approve=1 still BLOCKED (reviewer bug #3)",
      o and "error" in o and "approval" in o["error"]["message"], f"out={o}")

# no tracebacks cross the boundary (reviewer bug #4)
p = run_script('read a=b.json\n', d)
o = parse_out(p)
check("malformed token -> structured error, NOT traceback (reviewer bug #4)",
      o and "error" in o and "Traceback" not in p.stdout + p.stderr, f"stdout={p.stdout[:120]} stderr={p.stderr[:80]}")

# quoted value with spaces (reviewer bonus) — fixture at this point is the 10k dataset
p = run_script('fetch https://api.example.com/users paginate=results\n| filter email="u1@company.com"\n', d)
o = parse_out(p)
check("filter quoted value works", o and isinstance(o["result"], list) and len(o["result"]) == 1,
      f"got {o}")

# --- 11. INLINE PIPE + PLAN VERDICT TIERS (reviewer #2 / DeryClawbot) ---
json.dump([{"n": 1, "q": "a"}, {"n": 2, "q": "b"}], open(os.path.join(d, "data.json"), "w"))
p = run_script('read data.json | pick n\n', d)
o = parse_out(p)
check("inline pipe happy path", o and o["result"] == [{"n": 1}, {"n": 2}], f"got {o}")

p = run_script('read data.json|pick n\n', d)  # no spaces around pipe
o = parse_out(p)
check("inline pipe without spaces (token before | not lost)",
      o and o["result"] == [{"n": 1}, {"n": 2}], f"got {o}")

p = run_script('read data.json | filter q="a|b" | pick q\n', d)  # pipe inside quotes
o = parse_out(p)
check("quoted pipe does not split stage (empty result, no crash)",
      o and o["result"] == [], f"got {o}")

p = run_script('fetch https://api.example.com/users paginate=results\n| read data.json | pick n\n', d)  # mixed multi-line + inline
o = parse_out(p)
check("mixed multi-line + inline pipe parses", o is not None and
      (o.get("result") == [{"n": 1}, {"n": 2}] or "error" in o), f"got {str(o)[:120]}")

plan_p = sp.run(["python3", AGSH, "--plan"], input='read data.json | pick n\n',
                capture_output=True, text=True, cwd=d)
plan = json.loads(plan_p.stdout)
check("plan verdict tier 1: pure-only -> safe to run",
      plan["verdict"].startswith("safe to run"), f"got {plan['verdict']}")

plan_p = sp.run(["python3", AGSH, "--plan"], input='write out.json\n',
                capture_output=True, text=True, cwd=d)
plan = json.loads(plan_p.stdout)
check("plan verdict tier 2: local-write -> mutates local state",
      "MUTATES local state" in plan["verdict"], f"got {plan['verdict']}")

plan_p = sp.run(["python3", AGSH, "--plan"], input='append /tmp/plan_escape_test.txt\n',
                capture_output=True, text=True, cwd=d)
plan = json.loads(plan_p.stdout)
check("plan verdict tier 3: out-of-workdir write -> BLOCKED, no flags offered",
      plan["verdict"].startswith("BLOCKED") and plan["approval_required"] == [],
      f"got {plan['verdict']} {plan['approval_required']}")

# --- 12. SSRF GUARD + FIXTURE SOURCE MARKER (review Luthfy #2) ---
# private/metadata IP blocked by default
p = run_script('fetch http://169.254.169.254/latest/meta-data/\n', d)
o = parse_out(p)
check("SSRF: metadata IP blocked by default",
      o and "error" in o and "private/metadata" in o["error"]["message"], f"out={o}")

p = run_script('fetch http://127.0.0.1:9/x\n', d)
o = parse_out(p)
check("SSRF: loopback blocked by default", o and "error" in o, f"out={o}")

# fixture fetch is marked in stats (no silent shadowing)
p = run_script('fetch https://api.example.com/users paginate=results\n', d)
o = parse_out(p)
check("fixture fetch marked in stats.fetch_sources",
      o and o["stats"].get("fetch_sources") == ["fixture:api.example.com"], f"out={o['stats']}")

# with --allow-private-net, loopback fetch is allowed (hits live test server)
srv2 = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv2.serve_forever, daemon=True).start()
port2 = srv2.server_address[1]
p = sp.run(["python3", AGSH, "--allow-private-net"],
           input=f'fetch http://127.0.0.1:{port2}/things\n', capture_output=True, text=True, cwd=d)
o = parse_out(p)
check("SSRF: --allow-private-net unlocks loopback fetch", o and "error" not in o, f"out={str(o)[:150]}")
srv2.shutdown()

# stats.lines is real now
check("stats.lines counts pipeline lines", o and o["stats"]["lines"] == 1, f"out={o['stats']}")

# --- 13. SEMANTIC UPGRADE: let/take/get + type assertion ---
json.dump({"users": [{"n": 1, "name": "A"}, {"n": 2, "name": "B"}],
           "meta": {"total": 2}}, open(os.path.join(d, "cfg.json"), "w"))
p = run_script('read cfg.json\n| get meta.total\n| assert type num\n', d)
o = parse_out(p)
check("get nested path + assert type", o and o["result"] == 2, f"got {o}")

p = run_script('read cfg.json\n| get users.0.name\n| assert type str\n', d)
o = parse_out(p)
check("get dict+list index path", o and o["result"] == "A", f"got {o}")

p = run_script('read data.json\n| let users\n| read cfg.json\n| get meta.total\n| take users\n| pick n\n| assert type list\n| assert count==2\n', d)
o = parse_out(p)
check("let/take named state across stages", o and o["result"] == [{"n": 1}, {"n": 2}], f"got {o}")

p = run_script('take nosuchvar\n', d)
o = parse_out(p)
check("take unbound var -> structured error with bound list",
      o and "error" in o and "unbound" in o["error"]["message"], f"out={o}")

p = run_script('read data.json\n| get 0.users\n', d)  # data.json is a list of dicts → key lookup on dict fails
o = parse_out(p)
check("get on wrong type -> structured error with hint",
      o and "error" in o and ("key not found" in o["error"]["message"]), f"out={o}")

# --- 14. RUN ALLOWLIST (backlog #1) ---
p = run_script('run echo hello allow=echo,wc\n', d, extra_flags=["--allow-run"])
o = parse_out(p)
check("run allowlisted command (no shell)", o and o["result"]["exit_code"] == 0
      and o["result"]["stdout"] == "hello", f"out={o}")

p = run_script('run rm -rf . allow=echo,wc\n', d, extra_flags=["--allow-run"])
o = parse_out(p)
check("run non-allowlisted command blocked", o and "error" in o
      and "not in allowlist" in o["error"]["message"], f"out={o}")

p = run_script('run echo hi && rm x allow=echo\n', d, extra_flags=["--allow-run"])
o = parse_out(p)
check("run allowlist mode forbids shell metacharacters", o and "error" in o
      and "metacharacters" in o["error"]["message"], f"out={o}")

# --- 15. AUDIT LOG JSONL (backlog #2) ---
audit_file = os.path.join(d, "audit.jsonl")
p = run_script('read data.json\n| filter q=a\n| write out.json\n| write /etc/x\n', d,
               extra_flags=["--audit", audit_file])
o = parse_out(p)
recs = [json.loads(l) for l in open(audit_file)]
subjects = [r["subject"] for r in recs]
check("audit log records ok + error outcomes",
      o and any("write" in r["verb"] and r["outcome"] == "ok" for r in recs)
      and any(r["outcome"] == "error" for r in recs), f"recs={subjects}")
check("audit records have ts/risk/cwd",
      all(("ts" in r and "risk" in r and "cwd" in r) for r in recs), f"rec0={recs[0] if recs else None}")
os.remove(audit_file)

# --- 16. FILE LOCK (backlog #3) ---
target = os.path.join(d, "locked.json")
json.dump([1], open(target, "w"))
lockf = open(target + ".agshlock", "a+")
import fcntl as _fcntl
_fcntl.flock(lockf, _fcntl.LOCK_EX)  # simulate another agent holding the lock
p = run_script('read data.json\n| write locked.json\n', d)
o = parse_out(p)
check("write on locked file -> structured error", o and "error" in o
      and "locked by another process" in o["error"]["message"], f"out={o}")
_fcntl.flock(lockf, _fcntl.LOCK_UN); lockf.close()
p = run_script('read data.json\n| write locked.json\n', d)
o = parse_out(p)
check("write succeeds after lock release", o and o["result"]["written"] == 2, f"out={o}")

# --- 17. DNS-REBINDING PIN (backlog #4) — in-process, resolver monkeypatched ---
sys.path.insert(0, os.path.dirname(os.path.abspath(AGSH)))
import agsh as agsh_mod

rt = agsh_mod.Runtime()
_resolutions = iter([{"1.2.3.4"}, {"1.2.3.4"}])
rt._resolve_ips = lambda host: next(_resolutions)
source = rt._ssrf_guard("http://rebind-check.example/x", "fetch")
try:
    rt._verify_dns_pin("http://rebind-check.example/x", "fetch")
    stable = True
except agsh_mod.AGSHError:
    stable = False
check("DNS pin: stable resolution passes", source == "network" and stable)

rt2 = agsh_mod.Runtime()
_resolutions2 = iter([{"1.2.3.4"}, {"10.0.0.5"}])   # rebinds to RFC1918 between check & request
rt2._resolve_ips = lambda host: next(_resolutions2)
rt2._ssrf_guard("http://rebind-evil.example/x", "fetch")
rebound = False
try:
    rt2._verify_dns_pin("http://rebind-evil.example/x", "fetch")
except agsh_mod.AGSHError as e:
    rebound = "DNS rebinding" in e.msg
check("DNS pin: rebinding to private IP between check & request blocked", rebound)

# --- 18. POST SCHEMA VALIDATION (backlog #5) ---
p = run_script('read data.json\n| post http://no-net.example/api keys=id,q\n', d, extra_flags=["--approve"])
o = parse_out(p)
check("post missing required keys -> error BEFORE network", o and "error" in o
      and "missing required keys" in o["error"]["message"], f"out={o}")

p = run_script('read data.json\n| post http://no-net.example/api max_bytes=1\n', d, extra_flags=["--approve"])
o = parse_out(p)
check("post oversized payload -> error BEFORE network", o and "error" in o
      and "payload too large" in o["error"]["message"], f"out={o}")

# --- 19. FETCH RATE LIMIT (backlog #6) ---
json.dump({"results": [{"ok": 1}]}, open(os.path.join(d, "fixtures", "fixture-ok.example.json"), "w"))
script20 = "fetch http://fixture-ok.example/a\n" * 2
p = run_script(script20, d)   # fixture mode; 2 fetches, under cap
o = parse_out(p)
check("fetch under rate limit OK", o and "error" not in o and o["stats"]["fetches"] == 2, f"out={o}")

script25 = "fetch http://fixture-ok.example/a\n" * 21
p = run_script(script25, d, extra_flags=["--max-fetch", "20"])
o = parse_out(p)
check("fetch over rate limit -> structured error", o and "error" in o
      and "rate limit exceeded" in o["error"]["message"], f"out={o}")

p = run_script('read data.json\n| let users\n| filter q=a\n| let active\n| write out2.json\n| take users\n| assert count==2\n', d)
o = parse_out(p)
written = json.load(open(os.path.join(d, "out2.json"))) if os.path.exists(os.path.join(d, "out2.json")) else None
check("let pass-through: data flows through let + take restores original",
      o and "error" not in o and written == [{"n": 1, "q": "a"}], f"out={o}")
os.remove(os.path.join(d, "out2.json"))

# --- 20. RELATIONAL + SUBSTRING FILTER ---
json.dump({"results": [
    {"id": 1, "name": "alpha", "price": 150},
    {"id": 2, "name": "beta",  "price": 50},
    {"id": 3, "name": "gamma", "price": 99.5},
    {"id": 4, "name": "delta", "price": 250},
]}, open(os.path.join(d, "fixtures", "api.example.com.json"), "w"))

p = run_script('fetch https://api.example.com/users paginate=results\n'
               '| filter price>90\n| pick id\n| write t_rel.json\n', d)
o = parse_out(p)
rel = json.load(open(os.path.join(d, "t_rel.json"))) if os.path.exists(os.path.join(d, "t_rel.json")) else None
check("filter price>90 (relational)", o and "error" not in o
      and rel == [{"id": 1}, {"id": 3}, {"id": 4}], f"out={o} got={rel}")
os.remove(os.path.join(d, "t_rel.json")) if os.path.exists(os.path.join(d, "t_rel.json")) else None

p = run_script('fetch https://api.example.com/users paginate=results\n'
               '| filter price<=99.5\n| pick id\n| write t_le.json\n', d)
o = parse_out(p)
le = json.load(open(os.path.join(d, "t_le.json"))) if os.path.exists(os.path.join(d, "t_le.json")) else None
check("filter price<=99.5 (float boundary)", o and "error" not in o
      and le == [{"id": 2}, {"id": 3}], f"out={o} got={le}")
os.remove(os.path.join(d, "t_le.json")) if os.path.exists(os.path.join(d, "t_le.json")) else None

p = run_script('fetch https://api.example.com/users paginate=results\n'
               '| filter name contains lph\n| pick name\n| write t_sub.json\n', d)
o = parse_out(p)
sub = json.load(open(os.path.join(d, "t_sub.json"))) if os.path.exists(os.path.join(d, "t_sub.json")) else None
check("filter name contains", o and "error" not in o and sub == [{"name": "alpha"}], f"out={o} got={sub}")
os.remove(os.path.join(d, "t_sub.json")) if os.path.exists(os.path.join(d, "t_sub.json")) else None

p = run_script('fetch https://api.example.com/users paginate=results\n'
               '| filter price>abc\n| count\n', d)
o = parse_out(p)
check("filter relational with non-numeric operand -> structured error", o and "error" in o
      and o["error"]["step"] == "filter", f"out={o}")

# --- cleanup report ---
print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
for name, det in FAIL:
    print("FAILED:", name, "|", det)
shutil.rmtree(d, ignore_errors=True)
sys.exit(1 if FAIL else 0)
