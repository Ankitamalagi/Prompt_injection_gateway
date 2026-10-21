# Prompt Injection Security Gateway

A FastAPI service and browser dashboard for checking text for common prompt injection signals before an application sends it to an AI provider. It assigns a 0–100 risk score, applies a server-controlled policy, and writes a privacy-conscious audit record to SQLite.

## Features

- Preprocesses text and checks it against rule-based prompt-injection patterns.
- Calculates a 0–100 risk score and applies a server-controlled policy.
- Provides a browser dashboard and REST API for prompt analysis.
- Stores audit metadata and a SHA-256 prompt hash in SQLite; it does not store the submitted prompt text.
- Includes automated tests for detection, policy modes, API behavior, and audit privacy.
- Supports a rate-limited public demo and API-key-authenticated application integrations.
- Protects audit records with a separate administrator key and assigns app IDs from server configuration.
- Includes a non-root Docker image with a persistent data volume.

This is a learning prototype. It does not guarantee that a prompt is safe and does not forward prompts to an AI provider.

The `source` field is supplied by the caller. Its small scoring adjustment is a hint, not verified provenance; do not use it as an authorization or trust boundary.

## Requirements

- Python 3.10 or newer
- A terminal (VS Code's integrated terminal works)
- Docker, if you want to run the container image

## Setup and launch

From the project folder, create and activate a virtual environment so packages stay local to this project:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again. You can also install without activation with `.venv\Scripts\python -m pip install -r requirements-dev.txt`.

Start the app:

```powershell
python -m uvicorn main:app --reload
```

Open <http://127.0.0.1:8000> for the dashboard and <http://127.0.0.1:8000/docs> for interactive API documentation. Stop the server with Ctrl+C.

## How to use

Enter text in the dashboard and choose where it came from. Policy is controlled on the server with the `GATEWAY_POLICY` environment variable; the browser only displays the active setting. Request JSON fields named `policy` or `app_id` are ignored. The API accepts an optional bearer API key for registered applications. Without a key, requests use the public demo only when `GATEWAY_PUBLIC_DEMO=true` (the default).

Set `GATEWAY_POLICY` before starting Uvicorn. In PowerShell, for example:

```powershell
$env:GATEWAY_POLICY = "AUTO"
$env:GATEWAY_PUBLIC_DEMO = "true"
python -m uvicorn main:app --reload
```

Supported server modes are:

- `AUTO` (default): scores 0–30 ALLOW, 31–70 FLAG, and 71–100 BLOCK. Thresholds can be set with `FLAG_THRESHOLD` and `BLOCK_THRESHOLD`.
- `ALLOW`: allow every prompt. This is an administrator-only choice and disables automatic blocking, so use it only when that behavior is intentional.
- `FLAG`: flag prompts and block any score at or above the block threshold.
- `BLOCK`: block every prompt.
- `SANITIZE`: return a copy with known suspicious spans removed for every prompt. The gateway does not forward prompts to a model; the integrating application must decide what to do with that copy.

If `GATEWAY_POLICY` contains an unknown value, the application fails at startup instead of silently choosing a policy. The dashboard reads the active non-secret setting from `GET /api/config`. The API accepts `POST /api/analyze` with JSON such as `{"prompt":"Please summarize these notes."}`. Audit metadata is available at `GET /api/audit`.

### API and admin keys

For an application integration, configure a server-side mapping from app IDs to API keys. Generate a different random key for each app and a separate admin key; keep both in your hosting provider's secret settings, never in source code or Git. Keys must be at least 32 characters.

Example for a local PowerShell session (the commands generate random values into shell variables and do not print them):

```powershell
$apiKey = python -c "import secrets; print(secrets.token_urlsafe(32))"
$adminKey = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:GATEWAY_API_KEYS = ConvertTo-Json -Compress @{ "sample-app" = $apiKey }
$env:GATEWAY_ADMIN_KEY = $adminKey
```

The dashboard's API-key field is optional when the public demo is enabled. It sends an entered key as `Authorization: Bearer ...` and does not save it in browser storage. Enter the admin key in the audit section to view logs. The API uses the app ID mapped to the validated key rather than an ID supplied by the caller. `/api/audit` returns 503 if no admin key is configured and requires the correct `X-Admin-Key` header when configured.

Public demo requests are limited by client address (default 20 per minute); authenticated apps are limited by registered app ID (default 120 per minute). Configure these with `GATEWAY_DEMO_LIMIT_PER_MINUTE` and `GATEWAY_APP_LIMIT_PER_MINUTE`. The built-in limiter is per process. Put a managed rate limiter or reverse proxy limit in front of public deployments, especially if you run multiple instances.

### Run with Docker

The image runs as a non-root user and writes SQLite data under `/data`. Create persistent storage and build the image:

```powershell
docker volume create gateway-data
docker build -t prompt-injection-gateway .
```

Set `GATEWAY_API_KEYS` and `GATEWAY_ADMIN_KEY` in the shell as above, then start the container:

```powershell
docker run --rm -p 8000:8000 -v gateway-data:/data `
  --env GATEWAY_API_KEYS --env GATEWAY_ADMIN_KEY --env GATEWAY_PUBLIC_DEMO `
  prompt-injection-gateway
```

The volume preserves audit records across container restarts. For an internet-facing deployment, configure HTTPS and managed edge rate limiting at the host or reverse proxy. Do not expose the development server directly to the internet.

## Project files

- `main.py`: preprocessing, pattern rules, scoring, policy decision, REST endpoints, and SQLite audit storage.
- `static/`: HTML, CSS, and JavaScript dashboard.
- `tests/`: pytest checks for safe and suspicious prompts, policies, audit behavior, validation, and health endpoint.
- `requirements.txt`: Python packages needed to run the service.
- `requirements-dev.txt`: runtime requirements plus pytest and its HTTP test client.
- `Dockerfile` and `.dockerignore`: container build and safe build context.
- `.gitignore`: excludes local environments, secret/config files, databases, and generated files from Git.
- `gateway_logs.sqlite3`: created locally at runtime and excluded from Git; contains decision metadata and a SHA-256 prompt hash, not prompt text.
- `LICENSE`: MIT license for reuse and distribution.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Limitations

This project is a security prototype, not a guarantee that text is safe. It uses a short rule list and simple heuristics, with no trained ML classifier or provider forwarding; it can miss attacks and flag harmless text. The public demo and app quotas are in-memory and per process, so multi-instance deployments need an edge limiter. SQLite is suitable for a small, single-instance deployment with persistent storage; use managed database infrastructure for higher availability or concurrent multi-instance deployments. Audit hashes can still correlate repeated prompts. Production use also needs HTTPS, secret management, monitoring, backup and recovery plans, and regular adversarial testing. Never give an AI model unrestricted access to sensitive tools or data; enforce permissions in application code and require approval for high-impact actions.
