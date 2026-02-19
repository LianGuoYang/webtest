const form = document.getElementById("uploadForm");
const aiBox = document.getElementById("aiBox");
const historyList = document.getElementById("historyList");
const fileInput = document.getElementById("fileInput");

const scanBtn = document.querySelector("#uploadForm button");
scanBtn.disabled = true;

let scanHistory = [];

fileInput.addEventListener("change", function () {
  scanBtn.disabled = fileInput.files.length === 0;
});

form.addEventListener("submit", async function (e) {
  e.preventDefault();

  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";

  aiBox.innerHTML = "<div class='loading'>Scanning... please wait.</div>";

  try {
    const formData = new FormData(form);

    const res = await fetch("/", {
      method: "POST",
      body: formData
    });

    const data = await res.json();

    if (!res.ok || data.error || data.message) {
      const msg =
        data.error ??
        data.message ??
        data.detail ??
        "Request failed (HTTP " + res.status + ")";

      aiBox.innerHTML =
        "<div class='error'><b>Error:</b> " + msg + "</div>";
      return;
    }

    renderScanResult(data);

    // -------- Add to history --------
    let historyClass = "history-safe";
    if (data.malicious > 0) historyClass = "history-danger";
    else if (data.suspicious > 0) historyClass = "history-warning";

    scanHistory.unshift({
      filename: data.filename,
      verdict: data.verdict,
      className: historyClass
    });

    if (scanHistory.length > 20) scanHistory.pop();

    renderHistory();

  } catch (err) {
    const msg = err?.message || "Unexpected network error";
    aiBox.innerHTML =
      "<div class='error'><b>Error:</b> " + msg + "</div>";
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan File";
  }
});


// ===============================
// Render Scan Result (Structured)
// ===============================
function renderScanResult(data) {

  aiBox.innerHTML = "";

  // ---- Risk Badge ----
  let riskClass = "low";
  if (data.malicious > 0) riskClass = "high";
  else if (data.suspicious > 0) riskClass = "medium";

  aiBox.innerHTML += `
    <div class="risk-badge ${riskClass}">
      ${data.verdict}
    </div>

    <div class="section-title">Detection Breakdown</div>

    <div class="stat malicious">
      Malicious <span>${data.malicious}</span>
    </div>

    <div class="stat suspicious">
      Suspicious <span>${data.suspicious}</span>
    </div>

    <div class="stat harmless">
      Harmless <span>${data.harmless}</span>
    </div>

    <div class="stat undetected">
      Undetected <span>${data.undetected}</span>
    </div>

    <div class="section-title">AI Security Explanation</div>
  `;

  // ---- Parse AI Explanation ----
  let explanation = data.ai_explanation || "";
  let sections = explanation.split("\n\n").filter(s => s.trim() !== "");

  sections.forEach((section, index) => {

    let lines = section.split("\n");
    let title = lines[0];
    let content = lines.slice(1).join(" ");

    const block = document.createElement("div");
    block.className = "ai-block";

    block.innerHTML = `
      <div class="ai-title">• ${title}</div>
      <div class="ai-content ai-typing" id="ai-content-${index}"></div>
    `;

    aiBox.appendChild(block);

    typeWriter(
      document.getElementById(`ai-content-${index}`),
      content,
      18
    );

  });
}


// ===============================
// Typing Effect (Preserves Color)
// ===============================
function typeWriter(element, text, speed = 20) {

  const words = text.split(" ");
  let i = 0;

  function type() {
    if (i < words.length) {
      element.innerHTML += words[i] + " ";
      aiBox.scrollTop = aiBox.scrollHeight;
      i++;
      setTimeout(type, speed);
    } else {
      element.classList.remove("ai-typing");
    }
  }

  type();
}


// ===============================
// History Renderer
// ===============================
function renderHistory() {

  historyList.innerHTML = "";

  for (let i = 0; i < scanHistory.length; i++) {

    let item = scanHistory[i];

    historyList.innerHTML += `
      <div class="history-item">
        <div class="history-file">${item.filename}</div>
        <div class="history-verdict ${item.className}">
          ${item.verdict}
        </div>
      </div>
    `;
  }
}
