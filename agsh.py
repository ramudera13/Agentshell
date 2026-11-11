#!/usr/bin/env python3
"""AGSH — Agent Shell prototype interpreter.

Pipe-style DSL: verb subject key=value ... | verb ...
Verbs: fetch, post, read, write, append, filter, pick, map, search, run,
       ask, checkpoint, guard, undo, assert
All data flows as JSON. Mutations are logged for `undo`. Runtime returns
delta-feedback (written counts, diffs) instead of silent success.
"""
import json, os, sys, re, copy, time, socket, shlex, fcntl, datetime
import urllib.request, urllib.error
from contextlib import contextmanager

class AGSHError(Exception):
    def __init__(self, step, msg, hint=None, got=None):
        self.step, self.msg, self.hint, self.got = step, msg, hint, got
        super().__init__(f"[{step}] {msg}" + (f" | hint: {hint}" if hint else "") + (f" | got: {got}" if got is not None else ""))

def tokenize(line):
    """Split a pipeline line into stage TOKEN LISTS, honoring quotes:
    quotes group content (including spaces) into a single token, and quote
    characters are stripped."""
    stages, cur, buf, in_q, qch = [], [], "", False, None
    for c in line:
        if in_q:
            if c == qch:
                in_q = False
            else:
                buf += c
        elif c in "\"'":
            in_q, qch = True, c
        elif c == "|":
            if buf:
                cur.append(buf)
                buf = ""
            stages.append(cur)
            cur = []
        elif c in " \t":
            if buf:
                cur.append(buf)
                buf = ""
        else:
            buf += c
    if buf:
        cur.append(buf)
    if cur:
        stages.append(cur)
    # drop empty stages (e.g. leading "|" continuation lines)
    return [t for t in stages if any(tok != "|" for tok in t)]

def parse_stage(toks):
    verb, subject, kwargs = None, None, {}
    toks = [t for t in toks if t != "|"]  # continuation-pipe marker
    for i, t in enumerate(toks):
        if "==" in t and i > 1:
            pass  # equality op inside subject — never kwargs (PR-2: shadowing reorder)
        elif "=" in t and i > 0 and not re.search(r"(>=|<=|==|>|<)", t):
            k, v = t.split("=", 1)
            kwargs[k] = v
        elif i == 0:
            verb = t
        else:
            subject = (subject + " " + t) if subject else t
    return verb, subject, kwargs

class Runtime:
    def __init__(self, dry=False, allow_run=False, approve_network_write=False, answer=None,
                 allow_private_net=False, audit_path=None, max_fetch=20,
                 allow_llm=False, llm_base=None, llm_key=None, llm_model=None,
                 llm_max_input=8000):
        self.log = []          # undo log: [(kind, payload)]
        self.checkpoints = []  # indices into log
        self.allow_run = allow_run
        self.approve_network_write = approve_network_write
        self.answer = answer
        self.allow_private_net = allow_private_net
        self.allow_llm = allow_llm
        self.llm_base = llm_base
        self.llm_key = llm_key
        self.llm_model = llm_model
        self.llm_max_input = llm_max_input
        self.vars = {}         # named state across the pipeline (let/take)
        self.audit_path = audit_path
        self._dns_pins = {}    # host -> frozenset of IPs seen at guard time (DNS-rebinding defense)
        self.max_fetch = max_fetch
        self.stats = {"round_trips": 1, "lines": 0, "verbs": 0}

    # ---- audit log (append-only JSONL) ----
    def audit(self, verb, subject, outcome, extra=None):
        if not self.audit_path:
            return
        try:
            rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
                   "verb": verb, "risk": RISK.get(verb, "unknown"),
                   "subject": (subject or "")[:200], "outcome": outcome,
                   "cwd": os.getcwd()}
            if extra: rec.update(extra)
            with open(self.audit_path, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass  # auditing must never break the pipeline

    # ---- advisory file lock (multi-agent safety) ----
    @contextmanager
    def _file_lock(self, path, verb):
        lock_path = path + ".agshlock"
        try:
            f = open(lock_path, "a+")
        except OSError as e:
            raise AGSHError(verb, f"cannot create lock file: {e}", got=lock_path)
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            raise AGSHError(verb, f"file is locked by another process: {path}",
                            hint="another agent is writing this file — retry later (stale locks are safe to delete: *.agshlock)",
                            got=path)
        try:
            yield
        finally:
            try:
                fcntl.flock(f, fcntl.LOCK_UN)
            finally:
                f.close()

    # ---- undo-able mutations ----
    def _log_write(self, path, existed, prev_content):
        self.log.append(("write", {"path": path, "existed": existed,
                                   "prev": prev_content}))

    def _log_api(self, method, url, body, undo_method=None, undo_url=None):
        self.log.append(("api", {"method": method, "url": url, "body": body,
                                 "undo_method": undo_method, "undo_url": undo_url,
                                 "undone": False}))

    def undo_since(self, checkpoint=None):
        start = self.checkpoints[checkpoint] if isinstance(checkpoint, int) \
                and checkpoint < len(self.checkpoints) else \
                (self.checkpoints[-1] if self.checkpoints else 0)
        undone = []
        while len(self.log) > start:
            kind, payload = self.log.pop()
            if kind == "write":
                p = payload["path"]
                if payload["existed"]:
                    with open(p, "w") as f: f.write(payload["prev"])
                elif os.path.exists(p):
                    os.remove(p)
                undone.append(f"reverted file {p}")
            elif kind == "api" and not payload["undone"]:
                payload["undone"] = True
                um, uu = payload.get("undo_method"), payload.get("undo_url")
                if um and uu:
                    # REAL server-side undo (e.g. DELETE the created resource)
                    # — same SSRF guard as post: undo must never become an
                    # SSRF bypass via a crafted undo_url
                    try:
                        self._pin_host(uu, "undo")
                    except AGSHError as e:
                        undone.append(f"BLOCKED undo for {payload['method']} {payload['url']}: {e}")
                        continue
                    try:
                        req = urllib.request.Request(uu, method=um,
                            headers={"Content-Type": "application/json"})
                        body = json.dumps(payload.get("body")).encode() if um == "POST" else None
                        with urllib.request.urlopen(req, data=body, timeout=15) as r:
                            status = r.status
                        undone.append(f"undone API {payload['method']} {payload['url']} -> {um} {uu} (HTTP {status})")
                    except Exception as e:
                        undone.append(f"FAILED undo for {payload['method']} {payload['url']}: {e}")
                else:
                    undone.append(f"recorded undo intent for {payload['method']} {payload['url']} (no undo_method configured)")
        return undone

    # ---- built-ins ----
    PRIVATE_NET_RE = re.compile(
        r"^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|::1|fe80:|fc00:|fd)"
        r"|^172\.(1[6-9]|2\d|3[01])\.")

    def _url_host(self, url):
        return url.split("/")[2].split("@")[-1].split(":")[0]

    def _resolve_ips(self, host):
        return {i[4][0] for i in socket.getaddrinfo(host, None)}

    def _verify_dns_pin(self, url, verb):
        """DNS-rebinding defense: the IPs seen NOW must equal the IPs seen at
        guard time — otherwise the host may have rebound to a private IP."""
        host = self._url_host(url)
        now = self._resolve_ips(host)
        if now != self._dns_pins.get(host):
            raise AGSHError(verb, f"DNS rebinding suspected: {host} resolved to different IPs between check and request",
                            hint="blocked (TOCTOU defense); if intentional, re-run — but investigate the host", got=sorted(now))

    def _ssrf_guard(self, url, verb):
        """Resolve host and block private/metadata networks by default
        (prompt-injection defense: an agent must not be able to reach
        internal services or cloud metadata endpoints)."""
        host = url.split("/")[2].split("@")[-1].split(":")[0]
        if os.path.exists(os.path.join("fixtures", url.split("/")[2] + ".json")):
            return "fixture"
        if self.allow_private_net:
            self._dns_pins[host] = frozenset(self._resolve_ips(host))
            return "network"
        try:
            ips = self._resolve_ips(host)
        except Exception as e:
            raise AGSHError(verb, f"cannot resolve host: {host}", got=str(e))
        for ip in ips:
            if self.PRIVATE_NET_RE.match(ip):
                raise AGSHError(verb, f"host {host} resolves to private/metadata IP {ip}",
                                hint="blocked by default (SSRF guard); re-run with --allow-private-net if this is intentional",
                                got=ip)
        self._dns_pins[host] = frozenset(ips)  # pinned for rebinding check
        self.audit(verb, url, "ok", {"source": "network", "host": host})
        return "network"

    def _pin_host(self, url, verb):
        """Resolve + pin the host (must be called before any network write).
        Blocks private/metadata networks by default and pins resolved IPs so
        a later DNS-rebinding check can compare."""
        source = self._ssrf_guard(url, verb)
        if source == "network":
            self._verify_dns_pin(url, verb)
        return source

    def v_fetch(self, data, url, kw):
        if not re.match(r"https?://", url):
            raise AGSHError("fetch", "url must start with http(s)://", got=url)
        # rate limit (backlog #6): bounded fetches per run, host-configurable
        self.stats["fetches"] = self.stats.get("fetches", 0) + 1
        if self.stats["fetches"] > self.max_fetch:
            raise AGSHError("fetch", f"rate limit exceeded: more than {self.max_fetch} fetch stages in one run",
                            hint="raise --max-fetch on the host if this is intentional, or split the task",
                            got=self.stats["fetches"])
        source = self._pin_host(url, "fetch")
        self.stats.setdefault("fetch_sources", []).append(f"{source}:{url.split('/')[2]}")
        # offline demo mode: serve from ./fixtures/<host>.json if present
        fixture = os.path.join("fixtures", url.split("/")[2] + ".json")
        if os.path.exists(fixture):
            with open(fixture) as f:
                body = json.load(f)
            # a fixture is the whole dataset — no pagination
            self.stats["verbs"] += 1
            return body.get("results", body) if isinstance(body, dict) else body
        req = urllib.request.Request(url, headers={"Accept": "application/json",
            "User-Agent": kw.get("ua", "AGSH/0.3 (agent; +https://github.com/Bumbu-indomie13/AGSH-)")})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                body = json.loads(r.read().decode())
        except Exception as e:
            raise AGSHError("fetch", f"request failed: {e}", got=url)
        page_field = kw.get("paginate")
        out = body
        if page_field and isinstance(body, dict):
            results, page, failed = [], 1, None
            while True:
                chunk = body.get(page_field) if page == 1 else self._fetch_page(url, page_field, page)
                if chunk is None and page > 1:
                    failed = page
                    break
                if not chunk:
                    break
                results += chunk
                page += 1
                if page > 100:
                    # hard cap must be visible, never silent
                    raise AGSHError("fetch", "pagination hit the 100-page cap — results would be truncated",
                                    hint="narrow the query or raise the cap deliberately", got=f"{len(results)} rows")
            if failed:
                # silent truncation violates our own delta-feedback contract
                raise AGSHError("fetch", f"pagination failed at page {failed} — results may be incomplete",
                                hint="fix the API or remove paginate=", got=f"{len(results)} rows collected")
            out = results
        self.stats["verbs"] += 1
        return out

    def _fetch_page(self, url, field, page):
        sep = "&" if "?" in url else "?"
        # page requests bypass nothing: same SSRF/rebinding pin as the parent fetch
        self._pin_host(url, "fetch")
        try:
            req = urllib.request.Request(f"{url}{sep}page={page}", headers={
                "Accept": "application/json",
                "User-Agent": "AGSH/0.3 (agent; +https://github.com/Bumbu-indomie13/AGSH-)"})
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode()).get(field, [])
        except Exception:
            return None  # distinguishable from an empty page []

    def v_filter(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("filter", "input must be a list", got=type(data).__name__)
        if not (subject or "").strip() and not kw:
            raise AGSHError("filter", "no filter expression",
                            hint="use: filter FIELD=VALUE | filter FIELD>NUM | filter FIELD contains TEXT | filter FIELD ends-with TEXT", got=subject)
        # relational form: filter FIELD>NUM (also >= < <=) — numeric compare,
        # non-numeric/missing values simply don't match (consistent with =)
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)", (subject or "").strip())
        if m:
            f, op, num = m.group(1), m.group(2), float(m.group(3))
            ops = {">": lambda v: v > num, "<": lambda v: v < num,
                   ">=": lambda v: v >= num, "<=": lambda v: v <= num}
            def keep(x):
                try: return ops[op](float(x.get(f)))
                except (TypeError, ValueError): return False
            return [x for x in data if isinstance(x, dict) and keep(x)]
        # substring form: filter FIELD contains TEXT
        m = re.fullmatch(r"([A-Za-z_]\w*)\s+contains\s+(.*)", (subject or "").strip())
        if m:
            f, needle = m.group(1), m.group(2)
            return [x for x in data if isinstance(x, dict) and needle in str(x.get(f, ""))]
        # suffix form: filter FIELD ends-with TEXT (generic — was hardcoded to email)
        m = re.fullmatch(r"([A-Za-z_]\w*)\s+ends-with\s+(\S+)", (subject or "").strip())
        if m:
            f, suffix = m.group(1), m.group(2)
            return [x for x in data if isinstance(x, dict) and str(x.get(f, "")).endswith(suffix)]
        if kw:
            k, v = next(iter(kw.items()))
            return [x for x in data if isinstance(x, dict) and str(x.get(k)) == v]
        # equality form: filter FIELD == VALUE — string equality (PR-2, DeryClaw)
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*==\s*(.+)", (subject or "").strip())
        if m:
            f, val = m.group(1), m.group(2).strip().strip("\"'")
            return [x for x in data if isinstance(x, dict) and str(x.get(f)) == val]
        raise AGSHError("filter", "unsupported filter form",
                        hint="use: filter FIELD=VALUE | filter FIELD>NUM | filter FIELD contains TEXT | filter FIELD ends-with TEXT | filter FIELD==VALUE", got=subject)

    def v_pick(self, data, subject, kw):
        self.stats["verbs"] += 1
        fields = [f for f in re.split(r"[,\s]+", subject or "") if f]
        if isinstance(data, dict):
            return {k: data[k] for k in fields if k in data}
        out = []
        for x in data:
            if isinstance(x, dict):
                out.append({k: x[k] for k in fields if k in x})
            else:
                out.append(x)
        return out

    def _check_path(self, path, verb):
        """Sandbox: paths must stay inside the working directory."""
        real = os.path.realpath(path)
        root = os.path.realpath(os.getcwd())
        if not (real == root or real.startswith(root + os.sep)):
            raise AGSHError(verb, "path escapes working directory",
                            hint="write/read paths must stay inside the working dir", got=path)
        return real

    def v_write(self, data, subject, kw):
        self.stats["verbs"] += 1
        path = self._check_path(subject, "write")
        if data is None:
            raise AGSHError("write", "no input data to write",
                            hint="pipe data into write, e.g. '... | write targets.json'", got=subject)
        existed = os.path.exists(path)
        prev = open(path).read() if existed else None
        with self._file_lock(path, "write"), open(path, "w") as f:
            if isinstance(data, (list, dict)):
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))
        n = len(data) if isinstance(data, list) else 1
        # delta feedback vs previous version
        delta = None
        if existed:
            try:
                old = json.loads(prev)
                if isinstance(old, list): delta = n - len(old)
            except Exception: pass
        self._log_write(path, existed, prev)
        self.audit("write", subject, "ok", {"path": path, "written": n})
        fb = {"written": n, "path": path}
        if delta is not None: fb["diff_vs_previous"] = delta
        return fb

    def v_assert(self, data, subject, kw):
        self.stats["verbs"] += 1
        # type assertion (semantic contract between stages)
        m = re.match(r"type\s+(list|dict|str|num)", subject or "")
        if m:
            want = m.group(1)
            got = type(data).__name__
            ok = {"list": isinstance(data, list), "dict": isinstance(data, dict),
                  "str": isinstance(data, str),
                  "num": isinstance(data, (int, float)) and not isinstance(data, bool)}[want]
            if not ok:
                raise AGSHError("assert", f"expected type {want}, got {got}",
                                hint="check the previous stage's output shape", got=got)
            return data
        m = re.match(r"count\s*(>|<|>=|<=|==)\s*(\d+)", subject or "")
        if not m:
            raise AGSHError("assert", "unsupported assertion", got=subject)
        op, num = m.group(1), int(m.group(2))
        n = len(data) if isinstance(data, list) else 1
        ok = {">": n > num, "<": n < num, ">=": n >= num,
              "<=": n <= num, "==": n == num}[op]
        if not ok:
            hint = f"filter returned {n} — check field names exist" if n == 0 else None
            raise AGSHError("assert", f"count {n} not {op} {num}", hint=hint, got=n)
        return data

    def v_guard(self, data, subject, kw):
        self.stats["verbs"] += 1
        if subject.startswith("file exists"):
            path = subject.split("exists", 1)[1].strip()
            if not os.path.exists(path):
                raise AGSHError("guard", f"file not found: {path}", hint="create it or check the path", got=path)
            return data
        raise AGSHError("guard", "unsupported guard", got=subject)

    def v_let(self, data, subject, kw):
        """let NAME — bind current pipeline data to a named variable (data flows through)."""
        self.stats["verbs"] += 1
        if not re.fullmatch(r"[A-Za-z_]\w*", subject or ""):
            raise AGSHError("let", "variable name must be [A-Za-z_]word", got=subject)
        self.vars[subject] = data
        self.stats.setdefault("bound", []).append(subject)
        return data  # pass-through: a let in the middle of a pipeline must not break the flow

    def v_take(self, data, subject, kw):
        """take NAME — replace pipeline data with a previously bound variable."""
        self.stats["verbs"] += 1
        if subject not in self.vars:
            raise AGSHError("take", f"unbound variable: {subject}",
                            hint=f"bound so far: {sorted(self.vars) or 'none'}", got=subject)
        return self.vars[subject]

    def v_get(self, data, subject, kw):
        """get a.b.c — nested path access: dict keys and list indexes."""
        self.stats["verbs"] += 1
        cur = data
        for part in (subject or "").split("."):
            if part == "": continue
            if isinstance(cur, dict):
                if part not in cur:
                    raise AGSHError("get", f"key not found: {part}",
                                    hint=f"available keys: {sorted(cur)[:10]}", got=subject)
                cur = cur[part]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    raise AGSHError("get", f"bad list index: {part}",
                                    hint=f"list has {len(cur)} items (0..{len(cur)-1})", got=subject)
            else:
                raise AGSHError("get", f"cannot index into {type(cur).__name__} at '{part}'", got=subject)
        return cur

    def v_checkpoint(self, data, subject, kw):
        save = kw.get("save")
        if save:  # world-state checkpoint: data + snapshot of all tracked files
            path = self._check_path(save, "checkpoint")
            cwd = os.path.realpath(os.getcwd())
            files = {}
            for kind, payload in self.log:
                if kind == "write" and payload["path"] not in files:
                    p = payload["path"]
                    # store RELATIVE to cwd so the world file is portable
                    rel = os.path.relpath(p, cwd)
                    files[rel] = open(p).read() if os.path.exists(p) else None
            json.dump({"data": data, "files": files, "log_len": len(self.log)},
                      open(path, "w"), ensure_ascii=False)
            world = {"world_saved": path, "files": list(files)}
        else:
            world = None
        self.checkpoints.append(len(self.log))
        self.stats["verbs"] += 1
        return {"checkpoint": len(self.checkpoints) - 1, "world": world, "data": data}

    def v_resume(self, data, subject, kw):
        """Restore a world-state saved by `checkpoint save=FILE` (cross-session)."""
        self.stats["verbs"] += 1
        path = self._check_path(subject, "resume")
        if not os.path.exists(path):
            raise AGSHError("resume", f"world file not found: {subject}", got=subject)
        world = json.load(open(path))
        restored = []
        for p, content in world.get("files", {}).items():
            # validate EVERY path — a world file must never be an arbitrary
            # write primitive; paths are relative to cwd (portable)
            p = self._check_path(os.path.join(os.getcwd(), p), "resume")
            existed = os.path.exists(p)
            prev = open(p).read() if existed else None
            with self._file_lock(p, "resume"):
                if content is None:
                    if existed: os.remove(p)
                else:
                    open(p, "w").write(content)
            self._log_write(p, existed, prev)
            restored.append(p)
        self.audit("resume", subject, "ok", {"restored_files": restored})
        return {"resumed": subject, "restored_files": restored, "data": world.get("data")}

    def v_undo(self, data, subject, kw):
        undone = self.undo_since(kw.get("checkpoint", None) if kw.get("checkpoint", "").isdigit() else None)
        self.stats["verbs"] += 1
        self.audit("undo", subject or "last", "ok", {"undone": len(undone)})
        return {"undone": undone, "data": data}

    def v_read(self, data, subject, kw):
        self.stats["verbs"] += 1
        path = self._check_path(subject, "read")
        if not os.path.exists(path):
            raise AGSHError("read", f"file not found: {subject}", got=subject)
        content = open(path).read()
        try: return json.loads(content)
        except Exception: return content

    def v_run(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not self.allow_run:
            raise AGSHError("run", "shell execution is gated",
                            hint="inspect the plan (--plan), then re-run with --allow-run if approved",
                            got=subject)
        allow = kw.get("allow")
        if allow:
            # allowlist mode: no shell metacharacters, argv[0] must be in the
            # list, and the command runs WITHOUT a shell (no injection surface)
            allowed = {x.strip() for x in allow.split(",") if x.strip()}
            if re.search(r"[;&|<>`$(){}\[\]\\\n]", subject):
                raise AGSHError("run", "allowlist mode forbids shell metacharacters",
                                hint="each command must be a plain argv (no pipes, ;, &&, redirects)",
                                got=subject)
            argv0 = shlex.split(subject)[0]
            if argv0 not in allowed:
                raise AGSHError("run", f"command not in allowlist: {argv0}",
                                hint=f"allowed: {sorted(allowed)}; extend with allow=a,b in the script or ask the host for --allow-run approval",
                                got=argv0)
            import subprocess
            env = {"PATH": "/usr/bin:/bin", "HOME": os.getcwd(), "LANG": "C"}
            r = subprocess.run(shlex.split(subject), capture_output=True, text=True,
                               timeout=int(kw.get("timeout", 15)), env=env, cwd=os.getcwd())
        else:
            import subprocess
            # restricted execution: minimal env, working-dir-only cwd, hard timeout
            env = {"PATH": "/usr/bin:/bin", "HOME": os.getcwd(), "LANG": "C"}
            r = subprocess.run(subject, shell=True, capture_output=True, text=True,
                               timeout=int(kw.get("timeout", 15)), env=env, cwd=os.getcwd())
        self.audit("run", subject, "ok", {"exit_code": r.returncode, "allowlisted": bool(allow)})
        return {"exit_code": r.returncode, "stdout": r.stdout.strip()[:2000],
                "stderr": r.stderr.strip()[:2000]}

    def v_search(self, data, subject, kw):
        self.stats["verbs"] += 1
        out = []
        for root, dirs, files in os.walk("."):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    if subject in open(p, errors="ignore").read(): out.append(p)
                except Exception: pass
        return out

    # ---- LLM verb (bahasa): sub-pertanyaan dijawab DI DALAM pipeline ----
    def _llm_chat(self, system, user, kw, verb):
        """One OpenAI-compatible chat completion. Endpoint MUST be allowlisted
        by the host (--llm-base); the key comes from the host env, never the script."""
        import urllib.request
        base = (self.llm_base or os.environ.get("AGSH_LLM_BASE") or "").rstrip("/")
        key = self.llm_key or os.environ.get("AGSH_LLM_KEY") or ""
        model = kw.get("model") or self.llm_model or os.environ.get("AGSH_LLM_MODEL") or "default"
        if not base:
            raise AGSHError(verb, "no LLM endpoint configured",
                            hint="host must pass --llm-base http://host/v1 or set AGSH_LLM_BASE",
                            got=None)
        max_in = int(kw.get("max-input", self.llm_max_input))
        body_data = json.dumps(user, ensure_ascii=False) if not isinstance(user, str) else user
        if len(body_data.encode()) > max_in:
            # never send oversized prompts silently — truncate visibly & count
            body_data = body_data[:max_in]
            self.stats["llm_truncated_chars"] = self.stats.get("llm_truncated_chars", 0) + 1
        payload = {
            "model": model,
            "stream": False,  # 9router contract: without this the response is SSE even for non-chunk bodies
            "messages": ([{"role": "system", "content": system}] if system else [])
                        + [{"role": "user", "content": body_data}],
            "max_tokens": int(kw.get("max-tokens", 300)),
            "temperature": float(kw.get("temp", 0)),
        }
        req = urllib.request.Request(base + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {key}"})
        try:
            with urllib.request.urlopen(req, timeout=int(kw.get("timeout", 60))) as r:
                resp = json.loads(r.read().decode())
            msg = resp["choices"][0]["message"]
            content = msg.get("content") or ""
            finish = resp["choices"][0].get("finish_reason")
            usage = resp.get("usage", {})
            # reasoning models (deepseek-r1 style) may burn the whole token budget
            # on reasoning_content before emitting any content — retry visibly
            # with a larger budget instead of returning an empty answer
            retries = 0
            while not content.strip() and finish == "length" and retries < 2:
                retries += 1
                payload["max_tokens"] = int(payload["max_tokens"]) * 4
                req = urllib.request.Request(base + "/chat/completions",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {key}"})
                with urllib.request.urlopen(req, timeout=int(kw.get("timeout", 60))) as r:
                    resp = json.loads(r.read().decode())
                msg = resp["choices"][0]["message"]
                content = msg.get("content") or ""
                finish = resp["choices"][0].get("finish_reason")
                usage = resp.get("usage", {})
            self.stats["llm_budget_retries"] = self.stats.get("llm_budget_retries", 0) + retries
        except Exception as e:
            raise AGSHError(verb, f"LLM call failed: {e}",
                            hint="check the endpoint is up and the model name is valid", got=str(e)[:120])
        if not content.strip():
            raise AGSHError(verb, "LLM returned empty content (budget exhausted by reasoning)",
                            hint="raise max-tokens= (e.g. 1000) or use a non-reasoning model via model=",
                            got=f"finish_reason={finish}")
        self.stats["llm_calls"] = self.stats.get("llm_calls", 0) + 1
        self.stats["llm_prompt_tokens"] = self.stats.get("llm_prompt_tokens", 0) + usage.get("prompt_tokens", 0)
        self.stats["llm_completion_tokens"] = self.stats.get("llm_completion_tokens", 0) + usage.get("completion_tokens", 0)
        return content

    def v_llm(self, data, subject, kw):
        """llm "instruction" [model=NAME] [max-tokens=N] [max-input=N] [temp=F]
        Sends the pipeline data (JSON) with an instruction; the model's answer
        REPLACES the pipeline data. Deterministic: false is reported in stats."""
        self.stats["verbs"] += 1
        if not self.allow_llm:
            raise AGSHError("llm", "LLM calls are gated",
                            hint="host must re-run with --allow-llm (and --llm-base) if approved",
                            got=subject)
        if not subject:
            raise AGSHError("llm", "missing instruction",
                            hint='use: llm "kelompokkan error ini" max-tokens=200', got=None)
        if data is None:
            raise AGSHError("llm", "no input data — pipe something in (read/fetch first)",
                            hint="example: read log.jsonl | llm \"ringkas error\"", got=None)
        content = self._llm_chat(None, f"{subject}\n\nDATA:\n{data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)}", kw, "llm")
        self.audit("llm", subject, "ok", {"model": kw.get("model") or self.llm_model or "default"})
        # try to parse the answer as JSON (models often emit fenced blocks)
        txt = content.strip()
        if txt.startswith("```"):
            txt = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", txt).rstrip("`").strip()
        try:
            return json.loads(txt)
        except Exception:
            return content

    def v_summarize(self, data, subject, kw):
        """summarize [max-chars=N] — DETERMINISTIC compression, no LLM:
        reduces a long string/list into a compact head+tail window + stats,
        so the pipeline (and the chat context) only carries the small version."""
        self.stats["verbs"] += 1
        max_chars = int(kw.get("max-chars", 1200))
        if isinstance(data, list):
            if len(data) <= 20:
                return data
            head, tail = data[:10], data[-5:]
            out = {"summary": True, "total_items": len(data),
                   "head": head, "tail": tail,
                   "note": f"list compressed {len(data)} -> {len(head)+len(tail)} items (deterministic)"}
            self.stats["summarize_savings"] = self.stats.get("summarize_savings", 0) + len(data) - len(head) - len(tail)
            return out
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        if len(text) <= max_chars:
            return data
        cut = max_chars // 2
        out = {"summary": True, "original_chars": len(text),
               "head": text[:cut], "tail": text[-cut:],
               "note": f"text compressed {len(text)} -> {max_chars} chars (deterministic head+tail)"}
        self.stats["summarize_savings"] = self.stats.get("summarize_savings", 0) + len(text) - max_chars
        self.audit("summarize", (subject or "")[:80], "ok", {"original_chars": len(text)})
        return out

    def v_lines(self, data, subject, kw):
        """lines — split a text payload into a list of lines; each line is
        parsed as JSON when possible (JSONL logs become filterable lists).
        Pure/deterministic."""
        self.stats["verbs"] += 1
        if data is None:
            raise AGSHError("lines", "no input — pipe a text payload in (read a file first)", got=None)
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        out = []
        for ln in text.splitlines():
            if not ln.strip():
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                out.append(ln)
        return out

    def v_map(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("map", "input must be a list", got=type(data).__name__)
        out = []
        # forms: map field=newname=oldname | map upper email | map lower email | map strip email
        toks = (subject or "").split()
        if len(toks) == 2 and toks[0] in ("upper", "lower", "strip"):
            fn = {"upper": str.upper, "lower": str.lower, "strip": str.strip}[toks[0]]
            field = toks[1]
            for x in data:
                if isinstance(x, dict) and field in x:
                    x = dict(x); x[field] = fn(str(x[field]))
                out.append(x)
            return out
        if kw:  # map rename: newname=oldname
            new = next(iter(kw))
            old = kw[new].split("=")[-1]
            for x in data:
                if isinstance(x, dict) and old in x:
                    x = dict(x); x[new] = x.pop(old)
                out.append(x)
            return out
        raise AGSHError("map", "unsupported map form",
                        hint="use: map upper|lower|strip <field> or map newname=oldname", got=subject)

    def v_append(self, data, subject, kw):
        self.stats["verbs"] += 1
        subject = self._check_path(subject, "append")
        existed = os.path.exists(subject)
        prev = open(subject).read() if existed else ""
        with self._file_lock(subject, "append"), open(subject, "a") as f:
            f.write(json.dumps(data) + "\n" if isinstance(data, (dict, list)) else str(data) + "\n")
        self._log_write(subject, existed, prev)
        self.audit("append", subject, "ok", {"path": subject})
        return {"appended": True, "path": subject}

    def v_post(self, data, subject, kw):
        self.stats["verbs"] += 1
        # approval can ONLY come from the host CLI (--approve); a script can
        # never approve itself
        if not self.approve_network_write:
            raise AGSHError("post", "network write requires approval",
                            hint="show the plan (--plan) to the user, then re-run with --approve",
                            got=subject)
        # URL shape check first (cheap, no DNS), then payload validation, then
        # the full SSRF/rebinding pin (DNS) last — a malformed/oversized
        # payload must error BEFORE any DNS lookup or network call.
        if not re.match(r"https?://", subject or ""):
            raise AGSHError("post", "url must start with http(s)://", got=subject)
        undo_method = kw.get("undo_method")   # e.g. DELETE — real server call on undo
        undo_url = kw.get("undo_url")
        # schema validation (backlog #5): required keys + size cap BEFORE any
        # network call — a malformed/oversized payload never leaves the host
        payload = data if data is not None else {}
        if not isinstance(payload, (dict, list)):
            raise AGSHError("post", "payload must be a dict or list (pipe data in)", got=type(data).__name__)
        body = json.dumps(payload)
        max_bytes = int(kw.get("max_bytes", 1_000_000))
        if len(body.encode()) > max_bytes:
            raise AGSHError("post", f"payload too large: {len(body)} bytes (cap {max_bytes})",
                            hint="narrow the data first (pick/filter) or raise max_bytes=", got=len(body))
        required = kw.get("keys")
        if required:
            req_keys = [k.strip() for k in required.split(",") if k.strip()]
            if isinstance(payload, dict):
                items = [payload]
            elif all(isinstance(x, dict) for x in payload):
                items = payload
            else:
                raise AGSHError("post", "keys= requires a dict payload or a list of dicts",
                                got=type(payload).__name__)
            for it in items:
                missing = [k for k in req_keys if k not in it]
                if missing:
                    raise AGSHError("post", f"payload missing required keys: {missing}",
                                    hint="add keys= in the post stage listing all required fields",
                                    got=sorted(it.keys()))
        # SSRF + DNS-rebinding guard — network writes are the most dangerous
        # surface an agent has; a prompt-injected agent must not be able to
        # POST to internal services or cloud metadata endpoints. undo_url is
        # a second network-write surface and gets the same pin.
        self._pin_host(subject, "post")
        if undo_url:
            self._pin_host(undo_url, "post")
        # actually perform the POST
        body = body.encode()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json",
                "User-Agent": kw.get("ua", "AGSH/0.3 (agent; +https://github.com/Bumbu-indomie13/AGSH-)")}
        req = urllib.request.Request(subject, data=body, method="POST", headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, resp = r.status, r.read().decode()[:500]
        except Exception as e:
            raise AGSHError("post", f"request failed: {e}", got=subject)
        self._log_api("POST", subject, data, undo_method, undo_url)
        self.audit("post", subject, "ok", {"status": status,
                    "undo_method": undo_method, "payload_keys": list(payload) if isinstance(payload, dict) else None})
        return {"posted": subject, "status": status, "response": resp,
                "payload_keys": list(payload) if isinstance(payload, dict) else None}

    def v_ask(self, data, subject, kw):
        self.stats["verbs"] += 1
        if self.answer is not None:
            return {"question": subject, "answer": self.answer, "data": data}
        # human gate: stop the pipeline with dedicated exit code 2
        print(json.dumps({"needs_human": True, "question": subject,
                          "data": data, "stats": self.stats}, ensure_ascii=False))
        sys.exit(2)

    # ---- enhanced composition verbs (PR2 by @DeryClawbot) ----
    def v_sort(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("sort", "input must be a list", got=type(data).__name__)
        toks = (subject or "").split()
        desc = toks and toks[-1] == "desc"
        field = toks[0] if toks and toks[0] != "desc" else None
        if field:
            keyed = [x for x in data if isinstance(x, dict) and field in x]
            if len(keyed) != len(data):
                raise AGSHError("sort", f"field '{field}' missing in {len(data)-len(keyed)} items",
                                hint="all items must be dicts containing the field", got=field)
            return sorted(keyed, key=lambda x: x[field], reverse=desc)
        try:
            return sorted(data, reverse=desc)
        except TypeError:
            raise AGSHError("sort", "items are not comparable", got=type(data[0]).__name__ if data else None)

    def v_group(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("group", "input must be a list", got=type(data).__name__)
        out = {}
        for x in data:
            k = x.get(subject) if isinstance(x, dict) else None
            out.setdefault(str(k), []).append(x)
        return out

    def v_count(self, data, subject, kw):
        self.stats["verbs"] += 1
        n = len(data) if isinstance(data, (list, dict, str)) else (1 if data is not None else 0)
        return {"count": n}

    def v_head(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("head", "input must be a list", got=type(data).__name__)
        try:
            n = int(subject) if subject else 10
        except ValueError:
            raise AGSHError("head", "N must be an integer", hint="usage: head N", got=subject)
        if n <= 0:
            raise AGSHError("head", "N must be >= 1", hint="head -N is ambiguous and rejected; use tail for the end", got=subject)
        return data[:n]

    def v_tail(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("tail", "input must be a list", got=type(data).__name__)
        try:
            n = int(subject) if subject else 10
        except ValueError:
            raise AGSHError("tail", "N must be an integer", hint="usage: tail N", got=subject)
        if n <= 0:
            raise AGSHError("tail", "N must be >= 1", hint="tail -N is ambiguous and rejected", got=subject)
        return data[-n:]

    def v_uniq(self, data, subject, kw):
        self.stats["verbs"] += 1
        if not isinstance(data, list):
            raise AGSHError("uniq", "input must be a list", got=type(data).__name__)
        seen, out = set(), []
        for x in data:
            k = str(x.get(subject)) if isinstance(x, dict) and subject else json.dumps(x, sort_keys=True)
            if k not in seen:
                seen.add(k); out.append(x)
        return out

    def v_regex(self, data, subject, kw):
        self.stats["verbs"] += 1
        toks = (subject or "").split(None, 1)
        if len(toks) != 2:
            raise AGSHError("regex", "usage: regex FIELD PATTERN", got=subject)
        field, pat = toks
        try:
            rx = re.compile(pat)
        except re.error as e:
            raise AGSHError("regex", f"invalid pattern: {e}", hint="escape regex metacharacters or test the pattern separately", got=pat)
        if not isinstance(data, list):
            raise AGSHError("regex", "input must be a list", got=type(data).__name__)
        out = []
        for x in data:
            if isinstance(x, dict):
                x = dict(x)
                m = rx.search(str(x.get(field, "")))
                x[field + "_match"] = m.group(1) if (m and m.groups()) else (m.group(0) if m else None)
            out.append(x)
        return out

    def v_join(self, data, subject, kw):
        """join FILE KEY_A KEY_B - left-merge data list with list from FILE."""
        self.stats["verbs"] += 1
        toks = (subject or "").split()
        if len(toks) != 3:
            raise AGSHError("join", "usage: join FILE KEY_A KEY_B", got=subject)
        path = self._check_path(toks[0], "join")
        if not isinstance(data, list):
            raise AGSHError("join", "input must be a list", got=type(data).__name__)
        if not os.path.exists(path):
            raise AGSHError("join", f"file not found: {toks[0]}", got=toks[0])
        try:
            right = json.load(open(path))
        except json.JSONDecodeError as e:
            raise AGSHError("join", f"joined file is not valid JSON: {e}", got=toks[0])
        if not isinstance(right, list):
            raise AGSHError("join", "joined file must contain a JSON list", got=toks[0])
        ka, kb = toks[1], toks[2]
        index = {}
        for r in right:
            if isinstance(r, dict) and kb in r:
                index.setdefault(str(r[kb]), r)
        out = []
        for x in data:
            if isinstance(x, dict) and ka in x:
                r = index.get(str(x[ka]))
                if r:
                    merged = dict(x); merged.update(r)
                    out.append(merged); continue
            out.append(x)
        return out

    def execute_line(self, line, data=None):
        stages = tokenize(line)
        for toks in stages:
            verb, subject, kw = parse_stage(toks)
            fn = getattr(self, f"v_{verb}", None)
            if fn is None:
                raise AGSHError(verb, f"unknown verb '{verb}'",
                                hint="available: fetch post read write append filter pick map get let take search run ask checkpoint guard undo resume assert sort group count head tail uniq regex join llm summarize lines")
            try:
                data = fn(data, subject, kw)
                if verb not in ("fetch","write","post","run","append","undo","resume"):
                    self.audit(verb, subject, "ok")  # all-stage audit (PR-2, DeryClaw)
            except AGSHError:
                self.audit(verb, subject, "error")
                raise
        return data

# risk classes for the informed-permission plan
RISK = {
    "fetch": "network-read", "read": "local-read", "search": "local-read",
    "filter": "pure", "pick": "pure", "map": "pure", "assert": "pure",
    "guard": "pure", "write": "local-write", "append": "local-write",
    "post": "network-write", "run": "exec", "checkpoint": "safe",
    "undo": "mutating", "ask": "human", "resume": "mutating",
    "let": "pure", "take": "pure", "get": "pure",
    # LLM integration (Dery fork): llm = network call to an allowlisted endpoint,
    # summarize = deterministic compression (pure)
    "llm": "network-llm", "summarize": "pure", "lines": "pure",
    # PR2 composition verbs (by @DeryClawbot): pure unless reading a file
    "sort": "pure", "group": "pure", "count": "pure", "head": "pure",
    "tail": "pure", "uniq": "pure", "regex": "pure", "join": "local-read",
}

def build_plan(lines):
    stages = []
    for l in lines:
        for toks in tokenize(l):
            verb, subject, kw = parse_stage(toks)
            if not verb: continue
            risk = RISK.get(verb, "unknown")
            # detect sandbox escapes for path-mutating verbs at plan time
            if verb in ("write", "append") and subject:
                try:
                    real = os.path.realpath(subject)
                    root = os.path.realpath(os.getcwd())
                    if not (real == root or real.startswith(root + os.sep)):
                        risk = "sandbox-escape"
                except Exception:
                    pass
            stages.append({"verb": verb, "subject": (subject or "")[:80],
                           "risk": risk})
    counts = {}
    for s in stages: counts[s["risk"]] = counts.get(s["risk"], 0) + 1
    needs = []
    if counts.get("exec"): needs.append("--allow-run")
    if counts.get("network-write"): needs.append("--approve")
    if counts.get("network-llm"): needs.append("--allow-llm")
    if counts.get("sandbox-escape"):
        verdict = "BLOCKED: escapes sandbox (no flag can approve this)"
        needs = []
    elif needs:
        verdict = "needs approval: " + ", ".join(needs)
    elif counts.get("local-write") or counts.get("mutating"):
        verdict = "runs without flags but MUTATES local state"
    else:
        verdict = "safe to run (all stages read-only/pure)"
    return {"stages": stages, "summary": counts,
            "approval_required": needs, "verdict": verdict}

VERSION = "0.3.1-deryclaw.1"

def main():
    args = sys.argv[1:]
    if "--version" in args or "-V" in args:
        print(VERSION)
        return
    plan_only = "--plan" in args
    allow_run = "--allow-run" in args
    approve = "--approve" in args
    allow_private_net = "--allow-private-net" in args
    audit_path = None
    if "--audit" in args:
        audit_path = args[args.index("--audit") + 1]
    max_fetch = 20
    if "--max-fetch" in args:
        max_fetch = int(args[args.index("--max-fetch") + 1])
    answer = None
    if "--answer" in args:
        answer = args[args.index("--answer") + 1]
    allow_llm = "--allow-llm" in args
    llm_base = None
    if "--llm-base" in args:
        llm_base = args[args.index("--llm-base") + 1]
    llm_key = None
    if "--llm-key" in args:
        llm_key = args[args.index("--llm-key") + 1]
    llm_model = None
    if "--llm-model" in args:
        llm_model = args[args.index("--llm-model") + 1]
    llm_max_input = 8000
    if "--llm-max-input" in args:
        llm_max_input = int(args[args.index("--llm-max-input") + 1])
    rt = Runtime(allow_run=allow_run, approve_network_write=approve, answer=answer,
                 allow_private_net=allow_private_net, audit_path=audit_path,
                 max_fetch=max_fetch, allow_llm=allow_llm, llm_base=llm_base,
                 llm_key=llm_key, llm_model=llm_model, llm_max_input=llm_max_input)
    data = None
    src = sys.stdin.read()
    lines = [l.strip() for l in src.splitlines() if l.strip() and not l.strip().startswith("#")]
    rt.stats["lines"] = len(lines)
    if plan_only:
        print(json.dumps(build_plan(lines), indent=2, ensure_ascii=False))
        return
    for l in lines:
        try:
            data = rt.execute_line(l, data)
        except AGSHError as e:
            print(json.dumps({"error": {"step": e.step, "message": e.msg,
                                        "hint": e.hint, "got": e.got},
                              "stats": rt.stats}, ensure_ascii=False))
            sys.exit(1)
        except Exception as e:
            # contract: no tracebacks cross the boundary — even internal bugs
            print(json.dumps({"error": {"step": "?", "message":
                                        f"internal: {e.__class__.__name__}: {e}",
                                        "hint": "report this as a bug — internal error leaked"},
                              "stats": rt.stats}, ensure_ascii=False))
            sys.exit(1)
    out = {"result": data, "stats": rt.stats}
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
