# OWASP Mentor AI — Backend

FastAPI backend for the hackathon project **OWASP Mentor AI**: it safely inspects an uploaded ZIP of a student project, runs a limited static rule check, and explains findings in beginner-friendly language using a **local** Ollama model (with a deterministic fallback when Ollama is not running).

> **This is an automated, limited static check — not a complete security audit.** The browser session UUID (`X-Session-ID`) is only a demo ownership mechanism, **not authentication**.

## Important: the 13 requirements are placeholders

The organizers' exact list has not been supplied. `backend/app/security/rules.json` contains 13 clearly labelled placeholders (`OWASP-01`…`OWASP-13`), all `enabled: false`, so every result is `NOT_VERIFIED` and `official_list_verified` is `false`. Nothing is reported as compliant.

When you have the official list, edit `rules.json` (set `"official_list_verified": true` only once it is the real list). Example of an enabled rule:

```json
{
  "id": "OWASP-03",
  "title": "<official requirement wording>",
  "description": "Why this matters, in one or two sentences.",
  "severity": "HIGH",
  "enabled": true,
  "check_type": "regex_finding",
  "extensions": [".js", ".jsx"],
  "pattern": "\\beval\\s*\\(",
  "recommendation": "How to fix it."
}
```

| `check_type` | Match found | No match |
|---|---|---|
| `regex_finding` | `FINDING` (file, line, short evidence) | `NOT_VERIFIED` (absence of a pattern is not proof) |
| `regex_required` | `PASSED` (evidence of the control) | `FINDING` if in-scope files were scanned, else `NOT_VERIFIED` |
| `manual` / disabled | — | always `NOT_VERIFIED` |

Rules are data only; nothing in them is ever executed. Invalid rules fail loudly at startup. `counts` are per rule and always sum to the number of configured rules.

## Files

```
backend/app/main.py                  app factory, CORS, size limit, error handlers, health/rules/ai-status
backend/app/config.py                environment-based settings
backend/app/schemas.py               Pydantic models
backend/app/routers/scans.py         upload, history, report (session-scoped, rate-limited)
backend/app/services/zip_inspector.py  safe in-memory ZIP inspection
backend/app/services/scanner.py      rule engine
backend/app/services/ai_explainer.py Ollama client + fallbacks
backend/app/security/rules.json      the 13 placeholder rules
backend/tests/conftest.py            shared fixtures (extra file)
backend/tests/test_upload.py
backend/tests/test_security.py
requirements.txt  .env.example  .gitignore  README.md
```

Owned by a teammate and **not** modified here: `backend/app/database.py`, `models.py`, `crud.py`.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # .env is git-ignored
```

## Ollama (local AI, optional)

```bash
curl -fsSL https://ollama.com/install.sh | sh     # Linux (see ollama.com for other OS)
ollama pull qwen3:4b
ollama serve                                      # if it is not already running as a service
```

Keep Ollama bound to `127.0.0.1` (the default) — do not expose port 11434 publicly. The backend refuses a non-loopback `OLLAMA_BASE_URL` unless you explicitly set `OLLAMA_ALLOW_NON_LOCAL=true`. If Ollama or the model is missing, the app keeps working and uses fallback explanations.

Check it: `curl localhost:8000/api/ai/status`

## Database initialisation

Tables are created automatically at startup via `Base.metadata.create_all(bind=engine)` using your teammate's `Base`/`engine`.

## Run

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Swagger UI is off by default; set `ENABLE_DOCS=true` to enable `/docs` during development.

## Test

```bash
cd backend
python -m pytest -q
```

Tests use the real `Base`, `Scan` and `crud` functions on a throwaway in-memory SQLite database, mock Ollama with `httpx.MockTransport`, and never execute uploaded code.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | `{"status":"ok"}` |
| GET | `/api/rules` | configured rules + `official_list_verified` |
| POST | `/api/scans/upload` | multipart field `file`, header `X-Session-ID: <uuid>`; returns the full report |
| GET | `/api/scans?limit=20` | array of `{scan_id, filename, overall_status, counts, created_at}` for the session |
| GET | `/api/scans/{id}` | full report; `404` if missing **or** owned by another session |
| GET | `/api/ai/status` | `{provider, model, available, detail}` |

```bash
SID=$(python3 -c "import uuid;print(uuid.uuid4())")
curl -F "file=@DemoStore.zip" -H "X-Session-ID: $SID" http://localhost:8000/api/scans/upload
curl -H "X-Session-ID: $SID" http://localhost:8000/api/scans
curl -H "X-Session-ID: $SID" http://localhost:8000/api/scans/<scan_id>
```

Report shape (extra fields are additive to the agreed contract): `scan_id, filename, overall_status, counts{passed,failed,not_verified}, findings[...]`, plus `verification_complete, official_rules_verified, disclaimer, ai{...}, stats{...}`. Each finding has `rule_id, title, status, severity, file, line, evidence, explanation, recommendation` plus optional `explanation_source` (`static` | `ai` | `fallback`), `why_it_matters`, `safer_practice`, `secure_example`.

Upload errors: `400` bad/malformed/missing, `413` too large, `422` unsafe or over-limit archive, `429` rate limited. Error bodies are `{"detail": "..."}` with no tracebacks or paths.

## Frontend integration (React, `http://localhost:5173`)

- Generate one UUID per browser (`crypto.randomUUID()`), keep it in `localStorage`, send it as `X-Session-ID` on every request.
- Upload with `FormData` and field name `file`; do **not** set `Content-Type` manually.
- CORS allows only `FRONTEND_ORIGIN` exactly (`localhost` ≠ `127.0.0.1`).
- Uploads can take a while when AI is on (up to `AI_TOTAL_BUDGET`, default 120 s); use a long client timeout and a loading state.
- Render `explanation`, `why_it_matters`, `safer_practice` and `secure_example` as **plain text** (React's default escaping), never as HTML. AI text is explanatory, not verified evidence; show the `explanation_source` badge.
- Never show "compliant"/"secure" while `counts.not_verified > 0`; use `verification_complete`.

## Database integration assumptions

Calls use exactly `create_scan(db, scan_id, session_id, filename, status, report_json)`, `get_scan(db, scan_id, session_id)` and `list_scans(db, session_id, limit=20)`.

- `report_json` is passed as a **JSON string**. It works with a `Text` column or a `JSON` column (the reader accepts either).
- `get_scan` must return `None` when the scan does not exist or belongs to another session.
- Returned rows need a `report_json` attribute; `created_at` is used if present.

## Limits and safety

Max upload 10 MB · 300 entries · 20 MB uncompressed · 2 MB per file · compression ratio ≤ 100 · 1.5 M characters of source analysed. Allowed extensions: `.py .js .jsx .ts .tsx .html .css .json .xml .yaml .yml`. `node_modules`, `.git`, `dist`, `build` and similar folders are skipped.

Rejected outright: path traversal, absolute paths, symlinks/special files, encrypted entries, duplicate names, executables/libraries/bytecode/nested archives, and NUL-containing "source" files. Other non-source files (images, Markdown) are skipped. Archives are never extracted to disk, and nothing uploaded is executed, imported or passed to a shell.

## Known limitations

- Regex checks are shallow: they can miss issues and produce false positives. `PASSED` only means a configured pattern was found.
- Rule regexes come from `rules.json` (trusted config); an expensive regex could slow scans. Lines are capped at 2000 characters.
- Rate limiting is in-memory and per process; it ignores `X-Forwarded-For` (spoofable), so behind a reverse proxy all clients share one IP bucket.
- No authentication: anyone holding a session UUID can read that session's reports. Fine for a demo, not production.
- Local small models can be wrong; explanations are labelled and never alter statuses.
- Placeholder rules mean real scans currently return `NOT_VERIFIED` for everything.
