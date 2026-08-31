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

## REST API & Web Frontend

AI Kavach includes a unified FastAPI backend and an immersive React/Tailwind cybersecurity SOC terminal.

### 1. Launch the Application

```bash
# Step 1: Start Docker sandbox containers
docker compose up -d validator fuzzer

# Step 2: Start the AI Kavach Backend (serves API + Frontend UI)
py -3 -m api.main
```

### 2. Access AI Kavach

- **Web Frontend Terminal**: http://localhost:8000/ (or http://localhost:8000/ui)
- **Interactive Swagger Docs**: http://localhost:8000/docs
- **ReDoc API Reference**: http://localhost:8000/redoc
- **OpenAPI 3.0 Spec**: http://localhost:8000/openapi.json

*(Optional)* If hosting the frontend on an independent web server (e.g. `http://localhost:3000` or `http://localhost:5173`), CORS is pre-configured to communicate seamlessly with the backend API.

### 3. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Live health probe (Docker validator/fuzzer containers & LLM status) |
| `GET` | `/api/v1/targets` | List available scan targets with metadata |
| `POST` | `/api/v1/targets/upload` | Upload custom C/C++ source file or archive |
| `POST` | `/api/v1/scans` | Start a new async security scan |
| `GET` | `/api/v1/scans` | List all historical scans |
| `GET` | `/api/v1/scans/{id}` | Real-time scan telemetry, current stage, and live logs |
| `POST` | `/api/v1/scans/{id}/cancel` | Gracefully cancel a running scan |
| `GET` | `/api/v1/scans/{id}/findings` | Get structured vulnerability findings and patch diffs |
| `GET` | `/api/v1/scans/{id}/report` | Get JSON Proof-of-Fix report metadata |
| `GET` | `/api/v1/scans/{id}/report/html` | View/Download rendered HTML Proof-of-Fix report |
| `GET` | `/api/v1/scans/{id}/report/markdown` | Download Markdown report |
| `GET` | `/api/v1/scans/{id}/report/json` | Download JSON report |
| `GET` | `/api/v1/findings/{id}` | Get specific finding details by ID |

### 4. Example: Full Scan via API / Frontend

```bash
# 1. Create scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"targets/vuln_bof","timeout":30}'
# → {"scan_id":"8782aab5-...","status":"QUEUED",...}

# 2. Stream real-time status & stage logs
curl http://localhost:8000/api/v1/scans/8782aab5-...
# → {"status":"RUNNING","current_stage":"FUZZING","recent_logs":[...]}

# 3. Fetch verified findings and minimal diff patch
curl http://localhost:8000/api/v1/scans/8782aab5-.../findings

# 4. View or download HTML Proof-of-Fix report
curl http://localhost:8000/api/v1/scans/8782aab5-.../report/html
```

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
