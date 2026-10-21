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
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
    const sanitizedWrap = document.querySelector("#sanitized-wrap");
    sanitizedWrap.hidden = !body.sanitized_prompt;
    if (body.sanitized_prompt) document.querySelector("#sanitized").textContent = body.sanitized_prompt;
    resultPanel.hidden = false;
    await loadAudit();
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Analyze prompt";
  }
});

async function loadAudit() {
  const response = await fetch("/api/audit?limit=20");
  if (!response.ok) return;
  const data = await response.json();
  const rows = document.querySelector("#audit-rows");
  rows.replaceChildren();
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
}

loadAudit();
loadConfig();
