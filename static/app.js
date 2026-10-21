const form = document.querySelector("#analyze-form");
const resultPanel = document.querySelector("#result");
const submitButton = document.querySelector("#submit-button");
const errorBox = document.querySelector("#error");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.textContent = "";
  submitButton.disabled = true;
  submitButton.textContent = "Analyzing…";
  const data = {
    prompt: document.querySelector("#prompt").value,
    source: document.querySelector("#source").value,
  };
  const headers = { "Content-Type": "application/json" };
  const apiKey = document.querySelector("#api-key").value.trim();
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "The request could not be analyzed.");
    document.querySelector("#decision").textContent = body.decision;
    document.querySelector("#decision").className = `badge ${body.decision.toLowerCase()}`;
    document.querySelector("#score").textContent = body.risk_score;
    document.querySelector("#message").textContent = body.message;
    document.querySelector("#request-id").textContent = body.request_id;
    const list = document.querySelector("#rules");
    list.replaceChildren();
    if (body.detected_rules.length) {
      for (const rule of body.detected_rules) {
        const item = document.createElement("li");
        item.textContent = rule;
        list.append(item);
      }
    } else {
      const item = document.createElement("li");
      item.textContent = "No rules matched.";
      list.append(item);
    }
    const detectorList = document.querySelector("#detector-results");
    detectorList.replaceChildren();
    for (const detector of body.detector_results || []) {
      const item = document.createElement("li");
      const explanations = detector.signals.map((signal) => `${signal.name} (+${signal.score}): ${signal.explanation}`);
      item.textContent = `${detector.detector}: +${detector.score}${explanations.length ? ` — ${explanations.join("; ")}` : " (no signal)"}`;
      detectorList.append(item);
    }
    const sanitizedWrap = document.querySelector("#sanitized-wrap");
    sanitizedWrap.hidden = !body.sanitized_prompt;
    if (body.sanitized_prompt) document.querySelector("#sanitized").textContent = body.sanitized_prompt;
    resultPanel.hidden = false;
    if (document.querySelector("#admin-key").value) await loadAudit();
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Analyze prompt";
  }
});

async function loadAudit() {
  const adminKey = document.querySelector("#admin-key").value.trim();
  const status = document.querySelector("#audit-status");
  const rows = document.querySelector("#audit-rows");
  if (!adminKey) {
    rows.replaceChildren();
    status.textContent = "Enter the admin key configured by the gateway operator to view audit records.";
    return;
  }
  const response = await fetch("/api/audit?limit=20", { headers: { "X-Admin-Key": adminKey } });
  const data = await response.json();
  if (!response.ok) {
    rows.replaceChildren();
    status.textContent = data.detail || "Could not load audit records.";
    return;
  }
  rows.replaceChildren();
  status.textContent = "Audit records contain decision metadata and prompt hashes, not prompt text.";
  for (const entry of data.entries) {
    const row = document.createElement("tr");
    const values = [new Date(entry.timestamp).toLocaleString(), entry.source, entry.risk_score, entry.decision, entry.detected_rules.join(", ") || "—"];
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    rows.append(row);
  }
}

document.querySelector("#refresh-audit").addEventListener("click", loadAudit);

document.querySelector("#ask-provider-button").addEventListener("click", async () => {
  const errorBox = document.querySelector("#error");
  const button = document.querySelector("#ask-provider-button");
  const apiKey = document.querySelector("#api-key").value.trim();
  errorBox.textContent = "";
  if (!apiKey) {
    errorBox.textContent = "An application API key is required to use the AI provider.";
    return;
  }
  button.disabled = true;
  button.textContent = "Checking and sending…";
  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        prompt: document.querySelector("#prompt").value,
        source: document.querySelector("#source").value,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "The provider request failed.");
    document.querySelector("#provider-message").textContent = data.message;
    document.querySelector("#provider-answer").textContent = data.provider_response || "No provider response: gateway policy held this prompt.";
    document.querySelector("#provider-result").hidden = false;
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Analyze, then ask AI provider";
  }
});

async function loadConfig() {
  const response = await fetch("/api/config");
  if (!response.ok) return;
  const config = await response.json();
  document.querySelector("#policy").value = config.policy;
  const descriptions = {
    AUTO: `Automatic: allow below ${config.flag_threshold}, flag from ${config.flag_threshold}, and block from ${config.block_threshold}.`,
    ALLOW: "Server policy allows every prompt. Use only when an administrator has deliberately chosen this behavior.",
    FLAG: `Server policy flags prompts, but blocks scores at or above ${config.block_threshold}.`,
    BLOCK: "Server policy blocks every prompt.",
    SANITIZE: "Server policy returns a copy with known suspicious spans removed.",
  };
  document.querySelector("#policy-help").textContent = descriptions[config.policy];
  document.querySelector("#access-help").textContent = config.public_demo_enabled
    ? "The public demo is enabled. Application integrations can authenticate with an API key."
    : "The public demo is disabled. Enter an application API key to analyze prompts.";
  document.querySelector("#ask-provider-button").hidden = !config.provider_enabled;
}

loadAudit();
loadConfig();
