# Prompt Injection Security Gateway

A small local FastAPI service that checks text for common prompt injection signals, assigns a 0–100 risk score, applies a policy, and records an audit entry. It includes a browser dashboard and SQLite storage.

## Features

- Preprocesses text and checks it against rule-based prompt-injection patterns.
- Calculates a 0–100 risk score and applies a server-controlled policy.
- Provides a browser dashboard and REST API for prompt analysis.
- Stores audit metadata and a SHA-256 prompt hash in SQLite; it does not store the submitted prompt text.
- Includes automated tests for detection, policy modes, API behavior, and audit privacy.

This is a learning prototype. It does not guarantee that a prompt is safe and does not forward prompts to an AI provider.

## Requirements

- Python 3.10 or newer
- A terminal (VS Code's integrated terminal works)

## Setup and launch

From the project folder, create and activate a virtual environment so packages stay local to this project:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again. You can also install without activation with `.venv\Scripts\python -m pip install -r requirements.txt`.

Start the app:

```powershell
python -m uvicorn main:app --reload
```

Open <http://127.0.0.1:8000> for the dashboard and <http://127.0.0.1:8000/docs> for interactive API documentation. Stop the server with Ctrl+C.

## How to use

Enter text in the dashboard and choose where it came from. Policy is controlled on the server with the `GATEWAY_POLICY` environment variable; the browser only displays the active setting. Request JSON fields named `policy` are ignored, including values sent by older clients.

Set `GATEWAY_POLICY` before starting Uvicorn. In PowerShell, for example:

```powershell
$env:GATEWAY_POLICY = "AUTO"
python -m uvicorn main:app --reload
```

Supported server modes are:

- `AUTO` (default): scores 0–30 ALLOW, 31–70 FLAG, and 71–100 BLOCK. Thresholds can be set with `FLAG_THRESHOLD` and `BLOCK_THRESHOLD`.
- `ALLOW`: allow every prompt. This is an administrator-only choice and disables automatic blocking, so use it only when that behavior is intentional.
- `FLAG`: flag prompts and block any score at or above the block threshold.
- `BLOCK`: block every prompt.
- `SANITIZE`: return a copy with known suspicious spans removed for every prompt. The gateway does not forward prompts to a model; the integrating application must decide what to do with that copy.

If `GATEWAY_POLICY` contains an unknown value, the application fails at startup instead of silently choosing a policy. The dashboard reads the active non-secret setting from `GET /api/config`. The API accepts `POST /api/analyze` with JSON such as `{"prompt":"Please summarize these notes."}`. Audit metadata is available at `GET /api/audit`.

## Project files

- `main.py`: preprocessing, pattern rules, scoring, policy decision, REST endpoints, and SQLite audit storage.
- `static/`: HTML, CSS, and JavaScript dashboard.
- `tests/`: pytest checks for safe and suspicious prompts, policies, audit behavior, validation, and health endpoint.
- `requirements.txt`: Python packages needed to run and test the project.
- `.gitignore`: excludes local environments, secret/config files, databases, and generated files from Git.
- `gateway_logs.sqlite3`: created locally at runtime and excluded from Git; contains decision metadata and a SHA-256 prompt hash, not prompt text.

## Tests

```powershell
python -m pytest -q
```

## Limitations

This is a learning prototype, not a guarantee that text is safe. It uses a short rule list and simple heuristics; it has no trained ML classifier, provider forwarding, authentication, rate limiting, or multi-user deployment hardening. It can miss attacks and flag harmless text. Audit hashes may still be sensitive correlators. Keep the service on localhost and do not send private prompts unless you understand the risks. Add authentication and operational safeguards before exposing it to a network.
