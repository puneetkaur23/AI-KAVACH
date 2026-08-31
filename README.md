# 🛡️ AI Kavach — Cyber-Reasoning System (CRS)

> Autonomous vulnerability detection, root cause analysis, and patch generation with sandboxed proof-of-fix validation.

## Architecture

```
TARGET INGESTION
      │
      ├── FUZZING ENGINE (AFL++)
      ├── STATIC ANALYSIS (Semgrep)
      └── DYNAMIC ANALYSIS (ASan/UBSan)
             │
      CRASH TRIAGE (dedup → CWE → severity)
             │
      LLM REASONING LAYER (Gemini / GPT-4o / Ollama)
        ├── Root Cause Analysis
        └── Patch Generation (minimal diff)
             │
      SANDBOXED PATCH VALIDATOR (Docker)
        ├── Pre-patch crash reproduction ✓
        ├── Post-patch crash replay (must NOT crash) ✓
        └── Regression test suite (must ALL pass) ✓
             │
      PROOF-OF-FIX REPORT (HTML + Markdown)
```

## Quick Start

### Prerequisites

- **Docker Desktop** (Windows) — for the sandbox and fuzzer
- **Python 3.11+**
- **Google API key** (free at [aistudio.google.com](https://aistudio.google.com/app/apikey))

### Setup

```bash
# 1. Clone / open project
cd ai-kavach

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Configure API key
cp .env.example .env
# Edit .env and set GOOGLE_API_KEY=...

# 4. Build Docker sandbox (one-time)
docker compose build

# 5. Start containers
docker compose up -d validator fuzzer
```

### Run the Full Pipeline

```bash
# Run on buffer overflow target (60-second fuzz)
python kavach.py --target targets/vuln_bof --timeout 60

# Run on all targets
python kavach.py --all-targets --timeout 120

# Skip fuzzing (use pre-existing crashes)
python kavach.py --target targets/vuln_bof --skip-fuzzing

# Use local Ollama model (no API cost)
python kavach.py --target targets/vuln_bof --llm ollama

# Test without Docker (mock validator)
python kavach.py --target targets/vuln_bof --no-docker --skip-fuzzing
```

### Run Tests

```bash
# All test categories
python tests/run_tests.py

# Specific category
python tests/run_tests.py --category detection
python tests/run_tests.py --category patch
python tests/run_tests.py --category regression
python tests/run_tests.py --category system
```

## Project Structure

```
ai-kavach/
├── kavach.py                    # Single CLI entry point
├── models.py                    # Shared data models (pipeline contract)
├── requirements.txt
├── .env.example                 # API key template
├── docker-compose.yml
│
├── targets/                     # Deliberately vulnerable C programs
│   ├── vuln_bof/                # CWE-787 Buffer Overflow (D1)
│   ├── vuln_uaf/                # CWE-416 Use-After-Free (D2)
│   ├── vuln_intoverflow/        # CWE-190 Integer Overflow (D3)
│   ├── clean_target/            # No bugs (D4 — false positive test)
│   └── multi_bug/               # Two distinct bugs (D5 — dedup test)
│
├── fuzzing/
│   ├── run_fuzzer.sh            # AFL++ wrapper script
│   └── fuzzer_manager.py        # Python orchestration of Docker AFL++
│
├── static_analysis/
│   ├── run_semgrep.py           # Semgrep runner with caching
│   └── rules/custom_cwe.yaml   # Custom rules for CWE-787/416/190
│
├── triage/
│   └── triage_engine.py        # Dedup + CWE classify + severity rank
│
├── llm/
│   ├── llm_client.py            # Unified LLM client (Gemini/OpenAI/Ollama)
│   ├── orchestrator.py          # State machine: IDLE→TRIAGE→RCA→PATCH→VALIDATE
│   └── prompts/
│       ├── root_cause.txt       # RCA prompt template
│       └── patch_gen.txt        # Patch generation prompt template
│
├── sandbox/
│   ├── Dockerfile.validator     # Ubuntu + AFL++ + ASan + Python
│   └── validator.py             # 3-step patch validator (Docker)
│
├── reporting/
│   └── report_generator.py     # HTML + Markdown proof-of-fix reports
│
├── api/                         # REST API backend (FastAPI)
│   ├── main.py                  # FastAPI app with CORS, lifespan
│   ├── routes/
│   │   ├── health.py            # GET /health
│   │   ├── targets.py           # GET /api/v1/targets
│   │   ├── scans.py             # POST/GET /api/v1/scans
│   │   └── findings.py          # GET /api/v1/findings/{id}
│   ├── schemas/                 # Pydantic request/response models
│   └── services/
│       └── scan_service.py      # Async scan lifecycle management
│
├── tests/
│   ├── run_tests.py            # Full test suite (D/P/R/S categories)
│   └── test_api.py             # API endpoint tests (13 tests)
│
└── output/                      # Generated reports and logs
    ├── reports/
    └── kavach.log
```

## REST API

AI Kavach includes a FastAPI backend that wraps the CLI pipeline for frontend integration.

### Start the API Server

```bash
# Start Docker containers first
docker compose up -d validator fuzzer

# Start the API server (default: http://localhost:8000)
py -3 -m api.main

# Custom host/port
KAVACH_API_HOST=0.0.0.0 KAVACH_API_PORT=9000 py -3 -m api.main
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | System health check (Docker status, LLM config) |
| `GET` | `/api/v1/targets` | List available scan targets |
| `POST` | `/api/v1/scans` | Start a new async security scan |
| `GET` | `/api/v1/scans` | List all scans with status |
| `GET` | `/api/v1/scans/{id}` | Get scan status + summary |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/v1/scans/{id}/findings` | Get findings for a completed scan |
| `GET` | `/api/v1/scans/{id}/report` | Get structured JSON report |
| `GET` | `/api/v1/findings/{id}` | Get a specific finding by ID |

### Interactive API Docs

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI Spec**: http://localhost:8000/openapi.json

### Example: Create and Monitor a Scan

```bash
# 1. Create scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"targets/vuln_bof","timeout":60}'
# → {"scan_id":"abc-123","status":"QUEUED",...}

# 2. Poll status
curl http://localhost:8000/api/v1/scans/abc-123
# → {"status":"RUNNING",...} → {"status":"COMPLETED","findings_count":1,...}

# 3. Get findings
curl http://localhost:8000/api/v1/scans/abc-123/findings
# → {"findings":[{"severity":"CRITICAL","cwe":{"id":"CWE-121",...},...}]}

# 4. Get report
curl http://localhost:8000/api/v1/scans/abc-123/report
# → Full structured report JSON
```

### Frontend Integration

The API is designed for React/Vue/Angular frontends:

1. **CORS** is pre-configured for `localhost:3000`, `localhost:5173`, `localhost:8080`
2. Set `KAVACH_CORS_ORIGINS` env var for custom origins (comma-separated)
3. All responses are structured JSON with consistent error schemas
4. Scans run asynchronously — poll `GET /api/v1/scans/{id}` for status

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KAVACH_API_HOST` | `127.0.0.1` | API bind host |
| `KAVACH_API_PORT` | `8000` | API bind port |
| `KAVACH_CORS_ORIGINS` | `http://localhost:3000,...` | Allowed CORS origins |
| `KAVACH_LLM_PROVIDER` | `google` | LLM provider: google/openai/ollama |
| `GOOGLE_API_KEY` | — | Google Gemini API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API URL |

## LLM Providers

| Provider | Setup | Model (triage) | Model (reasoning) | Cost |
|----------|-------|----------------|-------------------|------|
| **Google** (default) | `GOOGLE_API_KEY` in `.env` | `gemini-2.0-flash` | `gemini-2.5-pro` | Free tier |
| **OpenAI** | `OPENAI_API_KEY` in `.env`, `pip install openai` | — | `gpt-4o` | Paid |
| **Ollama** | `ollama serve`, `ollama pull qwen2.5-coder` | `llama3.1:8b` | `qwen2.5-coder:14b` | Free (local) |

## Test Cases

| ID | Category | Scenario | Expected Outcome |
|----|----------|----------|------------------|
| D1 | Detection | Buffer overflow (CWE-787) | Found + classified |
| D2 | Detection | Use-after-free (CWE-416) | Found + classified |
| D3 | Detection | Integer overflow (CWE-190) | Found + classified |
| D4 | Detection | Clean target | No findings (0 false positives) |
| D5 | Detection | Two distinct bugs | Both found, deduped correctly |
| P3 | Patch | Patch minimality | Diff ≤ 5 lines changed |
| P4 | Patch | Bad patch rejection | Validator rejects, triggers retry |
| P5 | Patch | Budget exhaustion | Reports "could not patch" gracefully |
| R1 | Regression | Baseline tests pass | Green before any patching |
| R2 | Regression | Clean target tests | Always pass |
| S1 | System | Module imports | All modules importable |
| S2 | System | Empty ASan output | Triage handles gracefully |
| S3 | System | JSON serialization | CrashRecord serializes correctly |
| S4 | System | Semgrep YAML validity | Custom rules are valid YAML |
| S5 | System | Report generator | Initializes, creates output dir |

## Success Metrics

| Metric | Target |
|--------|--------|
| Detection rate | ≥ 4/5 seeded vulns found |
| False positive rate | 0% on clean target |
| Patch success rate | ≥ 80% of detected vulns |
| Regression safety | 100% of submitted patches pass |
| Time-to-patch | < 3 minutes per vuln |
| LLM calls per vuln | ≤ 5 |
| Max retries needed | ≤ 3 |

## Security Note

This project contains **deliberately vulnerable C programs** for security research and testing purposes. Do **not** deploy or run these vulnerable programs in a production environment. All fuzzing and validation runs inside a Docker sandbox.
