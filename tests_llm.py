#!/usr/bin/env python3
"""Tests for the new `llm` and `summarize` verbs (Dery fork)."""
import json, os, subprocess, tempfile, sys

AGSH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agsh.py")
PASS, FAIL = [], []

def run_script(script, cwd, flags=None):
    return subprocess.run(["python3", AGSH] + (flags or []), input=script,
                          capture_output=True, text=True, timeout=90, cwd=cwd)

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS" if cond else "FAIL"), "-", name, ("| " + detail if detail and not cond else ""))

d = tempfile.mkdtemp()

# big log fixture
lines = []
for i in range(500):
    lines.append(json.dumps({"ts": f"2026-11-12T0{i%10}:15:00Z", "status": "fail" if i % 7 == 0 else "ok",
                             "err": "ConnectionReset" if i % 7 == 0 else None}))
open(os.path.join(d, "log.jsonl"), "w").write("\n".join(lines))

# 1. gate: llm blocked without --allow-llm
p = run_script('read log.jsonl\n| llm "ringkas error" max-tokens=50\n', d)
o = json.loads(p.stdout)
check("llm gated without --allow-llm", "error" in o and o["error"]["step"] == "llm")

# 2. plan mode shows network-llm risk + requires --allow-llm
p = subprocess.run(["python3", AGSH, "--plan"], input='read log.jsonl\n| llm "x"\n| write out.json\n',
                   capture_output=True, text=True, cwd=d)
plan = json.loads(p.stdout)
check("plan marks llm as network-llm", plan["summary"].get("network-llm") == 1, str(plan["summary"]))
check("plan requires --allow-llm", "--allow-llm" in plan["approval_required"], str(plan["approval_required"]))

# 3. llm without input -> structured error
p = run_script('llm "halo"', d, ["--allow-llm"])
o = json.loads(p.stdout)
check("llm with no piped input -> structured error", "error" in o and o["error"]["step"] == "llm")

# 4. llm without endpoint -> structured error (gated but no base)
p = run_script('read log.jsonl\n| llm "x"\n', d, ["--allow-llm"])
o = json.loads(p.stdout)
check("llm without --llm-base -> structured error", "error" in o and "endpoint" in o["error"]["message"].lower())

# 5. REAL llm call against 9router
key = None
cfgp = os.path.expanduser("~/.hermes/config.yaml")
if os.path.exists(cfgp):
    import yaml
    key = (yaml.safe_load(open(cfgp)).get("model") or {}).get("api_key")
env = dict(os.environ, AGSH_LLM_BASE="http://127.0.0.1:20133/v1", AGSH_LLM_KEY=key or "",
           AGSH_LLM_MODEL="utama-1m")
p = subprocess.run(["python3", AGSH, "--allow-llm"], cwd=d, env=env,
                   input='read log.jsonl\n| lines\n| filter status=fail\n| count\n| llm "Berapa banyak error? Jawab satu kalimat." max-tokens=60\n',
                   capture_output=True, text=True, timeout=120)
try:
    o = json.loads(p.stdout)
except Exception:
    o = None
    print("RAW:", p.stdout[:300], p.stderr[:200])
check("real llm call returns answer", o and "result" in o and isinstance(o["result"], str) and len(o["result"]) > 3,
      str(o)[:200] if o else "no json")
check("llm stats recorded", o and o["stats"].get("llm_calls") == 1, str(o and o["stats"]))

# 6. summarize: deterministic text compression
big = json.dumps({"events": list(range(2000)), "blob": "x" * 30000})
open(os.path.join(d, "big.json"), "w").write(big)
p = run_script('read big.json\n| summarize max-chars=500\n| write small.json\n', d)
o = json.loads(p.stdout)
small = json.load(open(os.path.join(d, "small.json")))
check("summarize compresses text", isinstance(small, dict) and small.get("summary") is True
      and small["original_chars"] > 30000, str(small)[:150])
check("summarize stats record savings", o and o["stats"].get("summarize_savings", 0) > 29000, str(o and o["stats"]))

# 7. summarize: list compression
p = run_script('read big.json\n| get events\n| summarize\n| write ev.json\n', d)
o = json.loads(p.stdout)
ev = json.load(open(os.path.join(d, "ev.json")))
check("summarize compresses list 2000 -> 15", ev.get("total_items") == 2000 and len(ev["head"]) == 10 and len(ev["tail"]) == 5,
      str(ev)[:150])

# 8. summarize is pure: no flags needed
p = run_script('read big.json\n| summarize\n', d)
check("summarize needs no approval flag", "error" not in json.loads(p.stdout))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
sys.exit(1 if FAIL else 0)
