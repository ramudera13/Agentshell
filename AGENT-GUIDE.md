# AGSH — Panduan Integrasi untuk AI Agent

**Versi:** v0.2 | **Repo:** https://github.com/Bumbu-indomie13/AGSH-
**Untuk:** AI agent (Hermes, Claude, Cursor, dll) yang ingin memakai AGSH sebagai tool orkestrasi.

---

## 1. Apa itu AGSH

AGSH (Agent Shell) adalah pipe-style DSL yang dieksekusi interpreter deterministik di LUAR LLM. Agent menulis 3-6 stage pendek, runtime menjalankan semuanya dalam SATU eksekusi, dan mengembalikan JSON terstruktur + delta-feedback.

**Kapan pakai AGSH vs Python:**
- PAKAI AGSH: fetch API + filter/transform + simpan file, pagination, operasi file berulang, pipeline multi-langkah yang butuh verifikasi/undo.
- PAKAI Python: logika kompleks, perhitungan, parsing tidak standar (AGSH punya escape hatch `run`).

**Manfaat terukur:** 1 round-trip LLM menggantikan 5+ tool call; ~69% lebih hemat token (benchmark.py); error selalu structured (tanpa traceback); mutasi bisa di-undo.

## 2. Cara memanggil

Interpreter di mesin target: `/workspace/agsh/agsh.py` (stdlib-only, tidak perlu install apa pun).

```bash
printf '<pipeline AGSH>' | python3 /workspace/agsh/agsh.py [flags]
```

**Flag host (wajib untuk aksi berisiko — script TIDAK bisa meng-approve dirinya):**
- `--plan` — analisis tanpa eksekusi: risiko per stage + verdict. SELALU jalankan ini dulu untuk pipeline baru.
- `--allow-run` — buka verb `run` (shell, restricted env).
- `--approve` — buka verb `post` (network write).
- `--answer "TEXT"` — jawab gate `ask` (exit code 2).
- `--allow-private-net` — bypass SSRF guard (jarang perlu).

**Aturan loop yang benar:**
1. Tulis pipeline → jalankan `--plan`
2. Jika verdict `BLOCKED: escapes sandbox` → perbaiki path, JANGAN coba bypass
3. Jika `needs approval` → tampilkan ke user, tunggu persetujuan, baru eksekusi dengan flag
4. Jika sukses → baca `result` + `stats` (delta-feedback)

## 3. Verb reference (16 + 3 Dery-fork)

```
fetch URL [paginate=FIELD]     # HTTP GET JSON; auto-pagination; SSRF guard aktif
post URL [undo_method=DELETE] [undo_url=URL]   # butuh --approve; body = pipeline data
read FILE | write FILE | append FILE    # path-sandboxed ke working dir
filter FIELD=VALUE             # string equality
filter email ends-with X       # suffix match (quoted value utk spasi: filter name="John Smith")
pick f1,f2                     # project fields (missing = {})
map lower|upper|strip FIELD    # transformasi string
map NEWNAME=OLDNAME            # rename field
search TEXT                    # grep working dir
run CMD                        # BUTUH --allow-run; restricted: env minimal, timeout 15s
guard file exists PATH         # precondition
assert count >N               # postcondition (juga < >= <= ==); gagal = hint perbaikan
checkpoint [save=FILE]         # rollback point; save= = world-state lintas sesi
undo [checkpoint=N]            # revert mutasi sejak checkpoint (file byte-per-byte, API = real HTTP)
resume FILE                    # restore world-state di sesi baru
ask QUESTION                   # human gate: exit 2 + {"needs_human": true}
--- Dery fork (LLM integration) ---
llm "INSTRUKSI" [model=M] [max-tokens=N] [max-input=N] [temp=F]
                               # BUTUH --allow-llm + --llm-base; kirim pipeline data ke
                               # LLM OpenAI-compatible, jawaban menggantikan pipeline data.
                               # Auto-retry budget utk reasoning model; JSON answer auto-parse.
summarize [max-chars=N]        # DETERMINISTIC (tanpa LLM): kompres teks head+tail atau
                               # list 2000 -> 15 item. Pure, tanpa flag.
lines                          # pecah teks/JSONL jadi list baris (JSON per-baris auto-parse).
                               # Pure. Wajib sebelum filter utk file .jsonl/.log.
```

**Parsing contract:** value yang mengandung `=`, `>`, `<`, `|` WAJIB di-quote: `filter x="a>b"`. Inline pipe boleh: `read f.json|pick n` = `read f.json | pick n`.

## 4. Format output (kontrak untuk konsumen LLM)

Sukses:
```json
{"result": {"written": 4, "path": "targets.json", "diff_vs_previous": null},
 "stats": {"round_trips": 1, "lines": 1, "verbs": 5,
           "fetch_sources": ["fixture:api.example.com"]}}
```

Gagal (exit 1) — SELALU JSON, tidak pernah traceback:
```json
{"error": {"step": "assert", "message": "count 0 not > 0",
           "hint": "filter returned 0 — check field names exist", "got": 0}}
```

**Cara menangani error:** baca `hint` → perbaiki script → jalankan ulang. `got` = nilai aktual yang dilihat runtime. Jika `message` diawali `internal:` — laporkan sebagai bug interpreter, jangan di-retry.

**Exit codes:** 0 sukses | 1 error | 2 needs_human (baca `question`, tampilkan ke user).

## 5. Contoh siap pakai

Pipeline dasar:
```
fetch https://api.example.com/users paginate=results
| filter status=active
| filter email ends-with @company.com
| write targets.json
| assert count>0
```

Transformasi + rename:
```
fetch https://api.example.com/users paginate=results
| map lower email
| pick email
| map corporate_email=email
| write emails.json
```

Eksplorasi aman dengan rollback:
```
guard file exists users.json
| checkpoint
| read users.json
| filter status=active
| write active.json
| undo
```

## 6. Mode offline / testing

Buat file `fixtures/<host>.json` di working dir → `fetch` ke host itu menyajikan data fixture (dataset utuh, tanpa network). Sumber data SELALU terungkap di `stats.fetch_sources` (`fixture:<host>` vs `network:<host>`) — periksa ini sebelum mempercayai data.

## 7. Batasan yang harus agent ketahui

- Sandbox path: semua file ops TERBATAS ke working dir — path absolut/luar ditolak. Simpan hanya di cwd.
- SSRF: host yang resolve ke IP private/metadata diblok default.
- `undo` hanya merevert mutasi SETELAH checkpoint terakhir — urutan checkpoint penting.
- API undo butuh `undo_method`+`undo_url` eksplisit; tanpa itu hanya tercatat sebagai intent.
- `map` terbatas (lower/upper/strip/rename) — transformasi kompleks lewat `run` (butuh approval).
- SSRF: host yang resolve ke IP private/metadata diblok default; plus **DNS-rebinding pin** — resolusi ulang tepat sebelum request harus cocok dengan pin, kalau berbeda → error.
- `post` divalidasi **sebelum** network call: `keys=` (field wajib, termasuk utk list-of-dicts) + `max_bytes=` (default 1MB).
- Fetch dibatasi `--max-fetch N` per run (default 20) — kelebihan = structured error, bukan spam senyap.
- `run` allowlist mode (`run CMD allow=sort,wc`): no shell, argv allowlist, metacharacters rejected — mitigation for shell injection inside `--allow-run`.
- Audit log (`--audit PATH`): append-only JSONL of every stage outcome + network resolve (ts/verb/risk/subject/outcome/cwd).
- File locking: advisory flock on every mutation; concurrent agents get a structured lock error instead of silent corruption.
- Pagination cap 100 halaman; gagal/cap = structured error (tidak pernah truncate diam-diam).

## 8. Integrasi sebagai tool (pola wrapper)

Pola yang direkomendasikan untuk agent runtime — satu tool call per pipeline:

```
agsh_execute(script: str, plan_first: bool = true, flags: list[str] = [])
  -> jika plan_first: jalankan --plan dulu; jika verdict needs approval,
     kembalikan plan ke user; jika disetujui, eksekusi dengan flags.
```

Di Hermes: panggil via terminal/execute_code dengan printf pipe (lihat §2). Untuk distribusi luas, bungkus sebagai MCP server (`agsh --mcp`) — lihat roadmap repo.

## 9. Checklist sebelum dipercaya pada tugas nyata

1. `--plan` dijalankan dan verdict dipahami (bukan sekadar dilewati)
2. Approval disetujui USER, bukan dijawab oleh agent sendiri
3. Working dir bersih/dedikasi — semua file ops terkunci di situ
4. `checkpoint` dipasang sebelum mutasi yang mungkin di-undo
5. `stats.fetch_sources` diperiksa — jangan percaya data fixture bila mengira network
6. Test suite lulus di mesin target: `python3 tests.py` (60/60)

## 10. Menambah AGSH sebagai tool call di agent runtime

AGSH hanyalah program Python — membungkusnya jadi satu tool = satu file skill/wrapper. Pola minimal:

**Langkah 1 — buat wrapper** (`agsh_tool.py` di mesin agent):

```python
import json, subprocess

AGSH = "/workspace/agsh/agsh.py"

def agsh_execute(script: str, plan_first: bool = True, flags: list[str] | None = None):
    """Run one AGSH pipeline. Returns dict with result/error/stats.
    flags: host-level approvals, e.g. ["--approve"] — NEVER let the model
    add flags itself; they must come from user consent."""
    if plan_first:
        plan = json.loads(subprocess.run(
            ["python3", AGSH, "--plan"], input=script,
            capture_output=True, text=True, timeout=30).stdout)
        if plan["verdict"].startswith(("needs approval", "BLOCKED")):
            return {"needs_human": True, "plan": plan}
    r = subprocess.run(["python3", AGSH] + (flags or []), input=script,
                       capture_output=True, text=True, timeout=120)
    return json.loads(r.stdout)

# agent tool definition (JSON schema for your runtime):
# {"name": "agsh_execute",
#  "description": "Run a token-efficient AGSH pipeline: fetch/filter/transform/
#                  write files & APIs in ONE call. Use instead of multi-step
#                  code for orchestration tasks.",
#  "parameters": {"script": "string (the pipeline)",
#                 "flags": "array of host approval flags"}}
```

**Langkah 2 — daftarkan di runtime agent:**
- Hermes: simpan sebagai skill (`skill_manage`) yang memuat AGENT-GUIDE.md + wrapper; agent memanggil via execute_code/terminal.
- MCP-based runtime: expose `agsh_execute` sebagai satu MCP tool (roadmap: `agsh --mcp` stdio mode).

**Langkah 3 — aturan penggunaan (masukkan ke system prompt agent):**
1. Tugas orkestrasi (fetch/filter/transform/write) → tulis pipeline AGSH, bukan Python.
2. SELALU `--plan` dulu untuk script baru; tampilkan verdict ke user bila `needs approval`/`BLOCKED`.
3. Flag approval HANYA dari konsen user — agent tidak boleh menambahkan sendiri.
4. Error JSON dengan `hint` → perbaiki dan retry sekali; `internal:` → laporkan bug.

## 11. Menambah verb baru (prosedur disiplin)

Satu verb = satu method `v_<nama>` di class `Runtime` (`agsh.py`), signature TETAP:

```python
def v_sort(self, data, subject, kw):
    self.stats["verbs"] += 1
    if not isinstance(data, list):
        raise AGSHError("sort", "input must be a list", got=type(data).__name__)
    desc = kw.get("desc") == "1"
    key = subject or None
    return sorted(data, key=lambda x: (x.get(key) or 0) if isinstance(x, dict) else x,
                  reverse=desc)
```

**Checklist WAJIB (melewatkan satu = sandbox/gate bisa bolong, pelajaran dari bug `append`):**

1. Method `v_<nama>` di `Runtime` — raise `AGSHError` (jangan exception lain) untuk semua kegagalan.
2. Jika verb menyentuh file → panggil `self._check_path(path, "<nama>")`.
3. Jika verb melakukan network → tambahkan `self._ssrf_guard(url, "<nama>")` + gate approval jika write.
4. Entri di dict `RISK` (bawah file) — klasifikasi `pure/local-read/local-write/network-*/exec/human/mutating`.
5. Entri di SPEC.md (grammar + kontrak) dan README (tabel verb).
6. Test di `tests.py`: happy path + minimal satu negative/error case. Jalankan `python3 tests.py` sampai hijau.
7. Verb harus stdlib-only dan deterministic — tidak ada random/waktu-sistem di output.
Referensi implementasi terbaik: `v_get` (nested path, hint kaya), `v_let`/`v_take` (named state), `v_assert type` (kontrak tipe antar-stage).

---
AGSH v0.2 | MIT | 47 test, CI GitHub Actions | Repo: github.com/Bumbu-indomie13/AGSH-
