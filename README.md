# Prompt Injection Security Gateway

A FastAPI service and browser dashboard for checking text for common prompt injection signals before an application sends it to an AI provider. It assigns a 0–100 risk score, applies a server-controlled policy, and writes a privacy-conscious audit record to SQLite.

## Features

- Preprocesses text and checks it with an explainable, configurable detector pipeline (rule-based by default).
- Calculates a 0–100 risk score and applies a server-controlled policy.
- Provides a browser dashboard and REST API for prompt analysis.
- Stores audit metadata and a SHA-256 prompt hash in SQLite; it does not store the submitted prompt text.
- Includes automated tests for detection, policy modes, API behavior, and audit privacy.
- Supports a rate-limited public demo and API-key-authenticated application integrations.
- Protects audit records with a separate administrator key and assigns app IDs from server configuration.
- Includes a non-root Docker image with a persistent data volume.
- Offers an optional authenticated AI provider route; it stays disabled without server-side configuration.

This is a learning prototype. A gateway decision does not guarantee that a prompt is safe from prompt injection, and provider output is not independently verified by the gateway.

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
- `SANITIZE`: `POST /api/analyze` returns a copy with known suspicious spans removed. When the optional `/api/chat` route is enabled, it sends only that sanitized copy to the provider.

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
- `requirements-ai.txt`: optional official OpenAI Python SDK for provider-enabled deployments.
- `.env.example`: safe placeholders showing optional provider settings (the app reads process variables, not `.env` files directly).
- `detectors.py` and `providers.py`: modular detection and provider interfaces.
- `Dockerfile` and `.dockerignore`: container build and safe build context.
- `.gitignore`: excludes local environments, secret/config files, databases, and generated files from Git.
- `gateway_logs.sqlite3`: created locally at runtime and excluded from Git; contains decision metadata and a SHA-256 prompt hash, not prompt text.
- `LICENSE`: MIT license for reuse and distribution.

## Optional AI provider integration

The local dashboard and `POST /api/analyze` continue to work without provider credentials or the AI SDK. To enable provider forwarding, install the optional SDK and set the environment variables before starting Uvicorn:

```powershell
python -m pip install -r requirements-ai.txt
$env:AI_PROVIDER = "openai"
$env:OPENAI_BASE_URL = "https://api.openai.com/v1"
$env:OPENAI_MODEL = "your-model-name"
$providerSecret = Read-Host "Provider API key" -AsSecureString
$env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new("", $providerSecret).Password
Remove-Variable providerSecret
$gatewayKey = python -c "import secrets; print(secrets.token_urlsafe(32))"
Set-Clipboard $gatewayKey
$env:GATEWAY_API_KEYS = ConvertTo-Json -Compress @{ "local-app" = $gatewayKey }
python -m uvicorn main:app --reload
```

Replace the model name with one supported by your provider. `OPENAI_BASE_URL` can point to another OpenAI-compatible service. `.env.example` lists the variable names and safe placeholders; this application does not automatically read `.env` files. The generated gateway key is copied to the clipboard so you can paste it into the dashboard's application-key field. Keep real credentials in process environment variables or a deployment secret manager. Never put real values in `.env.example` or commit a `.env` file.

The provider key and model are read only by the server:

- `AI_PROVIDER=openai` enables the OpenAI-compatible provider. The default `none` keeps provider access off.
- `OPENAI_API_KEY` is read only by the server and is never returned, logged, or sent to browser code.
- `OPENAI_MODEL` selects the model. `OPENAI_BASE_URL` is optional for an operator-managed OpenAI-compatible endpoint.
- `AI_PROVIDER_TIMEOUT_SECONDS` sets the request timeout (1–120 seconds; default 20).
- `GATEWAY_FLAG_PROVIDER_ACTION` is `block` by default. Set it to `allow` only if the server operator explicitly wants FLAGged prompts sent.

The dashboard's **Analyze, then ask AI provider** button requires the registered gateway key in its application-key field. That key is different from the provider key; the provider key is never entered into the dashboard.

Provider calls use `POST /api/chat` with the same prompt/source JSON as `/api/analyze`, and require a registered application Bearer key even if the anonymous public demo is enabled. The route runs preprocessing, detection, policy enforcement, and audit logging first:

- `BLOCK`: the provider is not called.
- `FLAG`: held by default; sent as normalized text only when the server sets `GATEWAY_FLAG_PROVIDER_ACTION=allow`.
- `SANITIZE`: sends only the normalized copy after the current matching rule spans are replaced by `[removed suspicious instruction]`. This simple regex replacement can remove useful text and is not a proof of safety.
- `ALLOW`: sends the normalized prompt.

Provider errors return generic gateway messages (502 for provider failures or invalid responses, 504 for timeout, 503 when provider setup is unavailable), together with the security decision and score. A blocked or held request returns its security result and says the provider was not called. The SDK is configured without automatic retries to avoid repeating paid requests. The provider response is returned to the authenticated caller and is not written to SQLite. Enabling this option sends permitted prompt content to the configured external provider; review its privacy and retention terms before use. For an AI-enabled Docker image, build with `docker build --build-arg INSTALL_AI=true -t prompt-injection-gateway .` and pass provider settings at container runtime.

## Detection pipeline

`detectors.py` defines the `Detector` interface, a registry, and result types. `RuleDetector` is the only implemented detector today. `GATEWAY_DETECTORS=rules` selects the pipeline (comma-separated registered names); unknown names fail startup rather than being silently ignored. To load operator-maintained plugin modules that register detectors, set `GATEWAY_DETECTOR_MODULES=package.module` (multiple comma-separated module names are supported) before startup. Each response includes `active_detectors` and `detector_results`, which show the score and named signals from each detector. The existing `detected_rules` field remains available for older clients. Caller-reported source penalties are also reported separately and are unverified metadata. No machine-learning model is implemented or enabled.

New detectors can implement `inspect(normalized_prompt)` and register their class with `register_detector`; their module can be imported with `GATEWAY_DETECTOR_MODULES`. Scores are added and capped at 100. Treat detector plugin modules as trusted server code.

## Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The tests use a mocked provider and make no paid API calls. You do not need `requirements-ai.txt` or a real provider key to run them.

## Limitations

This project is a security prototype, not a guarantee that text is safe. Its short rule list and simple heuristics can miss attacks and flag harmless text. The provider integration is optional, sends approved prompt text to an external service, and cannot guarantee the model's response is safe. The public demo and app quotas are in-memory and per process, so multi-instance deployments need an edge limiter. SQLite is suitable for a small, single-instance deployment with persistent storage; use managed database infrastructure for higher availability or concurrent multi-instance deployments. Audit hashes can still correlate repeated prompts. Production use also needs HTTPS, secret management, monitoring, backup and recovery plans, and regular adversarial testing. Never give an AI model unrestricted access to sensitive tools or data; enforce permissions in application code and require approval for high-impact actions.
