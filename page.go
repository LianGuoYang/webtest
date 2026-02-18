package main

import (
	"fmt"
	"net/http"
)

func renderPage(w http.ResponseWriter) {

	fmt.Fprint(w, `
<html>
<head>
<style>
* {
  box-sizing: border-box;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

body {
  margin: 0;
  background: linear-gradient(135deg, #0f172a, #1e293b);
  color: #f1f5f9;
}

h2 {
  text-align: center;
  margin: 40px 0;
  font-weight: 600;
}

.container {
  display: flex;
  justify-content: center;
  gap: 30px;
  padding: 0 40px 60px 40px;
}

.history {
  width: 260px;
  background: #1e293b;
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.4);
  max-height: 700px;
  overflow-y: auto;
}

.history-item {
  padding: 10px;
  border-radius: 8px;
  margin-bottom: 10px;
  background: rgba(255,255,255,0.03);
  font-size: 13px;
  cursor: default;
}

.history-file {
  font-weight: 600;
  margin-bottom: 4px;
  word-break: break-word;
}

.history-verdict {
  font-size: 12px;
  font-weight: 600;
}

.history-danger {
  color: #ef4444;
}

.history-warning {
  color: #facc15;
}

.history-safe {
  color: #22c55e;
}

.left, .right {
  background: #1e293b;
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.4);
}

.left {
  width: 320px;
}

.right {
  width: 700px;
  min-height: 500px;
}

input[type="file"] {
  width: 100%;
  padding: 10px;
  background: #0f172a;
  color: #f1f5f9;
  border: 1px solid #334155;
  border-radius: 6px;
}

button {
  width: 100%;
  padding: 12px;
  margin-top: 15px;
  background: linear-gradient(90deg, #3b82f6, #6366f1);
  border: none;
  border-radius: 6px;
  color: white;
  font-weight: 600;
  cursor: pointer;
  transition: 0.3s ease;
}

button:hover {
  opacity: 0.85;
}

.small {
  margin-top: 8px;
  font-size: 12px;
  color: #94a3b8;
  text-align: center;
}

.ai-box {
  padding: 20px;
  background: #0f172a;
  border-radius: 8px;
  min-height: 550px;
  font-size: 14px;
  line-height: 1.6;
  overflow-y: auto;
}

/* Section title */
.section-title {
  margin-top: 18px;
  margin-bottom: 8px;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: #94a3b8;
}

/* Verdict badge */
.risk-badge {
  display: inline-block;
  padding: 6px 14px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 700;
  margin-bottom: 15px;
}

.high {
  background: #ef4444;
  color: white;
}

.medium {
  background: #facc15;
  color: black;
}

.low {
  background: #22c55e;
  color: white;
}

/* Stat rows */
.stat {
  display: flex;
  justify-content: space-between;
  padding: 6px 12px;
  margin-bottom: 6px;
  border-radius: 8px;
  font-weight: 500;
  background: rgba(255,255,255,0.03);
  font-size: 13px;
}

.stat span {
  font-weight: 700;
}

.ai-block {
  margin-bottom: 18px;
}

.ai-title {
  font-weight: 600;
  margin-bottom: 6px;
  color: #93c5fd;
}

.ai-content {
  padding-left: 16px;
  color: #e2e8f0;
  line-height: 1.6;
}

.malicious {
  color: #ef4444;
  background: rgba(239,68,68,0.1);
}

.suspicious {
  color: #facc15;
  background: rgba(250,204,21,0.1);
}

.harmless {
  color: #22c55e;
  background: rgba(34,197,94,0.1);
}

.undetected {
  color: #60a5fa;
  background: rgba(96,165,250,0.1);
}

.error {
  color: #f87171;
}

.loading {
  opacity: 0.7;
  font-style: italic;
}
</style>
</head>
<body>

<h2>VirusTotal Scanner + Gemini AI Explanation</h2>

<div class="container">
  <div class="left">
    <form id="uploadForm">
      <input type="file" name="file" required />
      <br><br>
      <button type="submit">Scan File</button>
      <div class="small">Max 10MB</div>
    </form>
  </div>

  <div class="right">
    <div class="ai-box" id="aiBox">No scan yet.</div>
  </div>
  <div class="history">
  <div class="section-title">Scan History</div>
  <div id="historyList"></div>
</div>

<script>
  const form = document.getElementById("uploadForm");
  const aiBox = document.getElementById("aiBox");
  const historyList = document.getElementById("historyList");

  let scanHistory = [];   // must be global (outside submit)

  form.addEventListener("submit", async function(e) {
    e.preventDefault();

    aiBox.innerHTML = "<div class='loading'>Scanning... please wait.</div>";

    try {
      const formData = new FormData(form);

      const res = await fetch("/", {
        method: "POST",
        body: formData
      });

      const data = await res.json();   // ✅ parse FIRST

      if (!res.ok || data.error) {
        const msg = data.error || ("Request failed (HTTP " + res.status + ")");
        aiBox.innerHTML = "<div class='error'><b>Error:</b> " + msg + "</div>";
        return;
      }

      // -------------------------
      // Risk badge logic
      // -------------------------
      let riskClass = "low";
      if (data.malicious > 0) riskClass = "high";
      else if (data.suspicious > 0) riskClass = "medium";

      // -------------------------
      // Format AI explanation
      // -------------------------
      let explanation = data.ai_explanation || "";
      let sections = explanation.split("\n\n").filter(s => s.trim() !== "");
      let formattedAI = "";

      for (let i = 0; i < sections.length; i++) {
        let lines = sections[i].split("\n");
        let title = lines[0];
        let content = lines.slice(1).join(" ");

        formattedAI +=
          "<div class='ai-block'>" +
            "<div class='ai-title'>• " + title + "</div>" +
            "<div class='ai-content'>" + content + "</div>" +
          "</div>";
      }

      // -------------------------
      // Render main AI box
      // -------------------------
      aiBox.innerHTML =
        "<div class='risk-badge " + riskClass + "'>" +
          data.verdict +
        "</div>" +

        "<div class='section-title'>Detection Breakdown</div>" +

        "<div class='stat malicious'>Malicious <span>" + data.malicious + "</span></div>" +
        "<div class='stat suspicious'>Suspicious <span>" + data.suspicious + "</span></div>" +
        "<div class='stat harmless'>Harmless <span>" + data.harmless + "</span></div>" +
        "<div class='stat undetected'>Undetected <span>" + data.undetected + "</span></div>" +

        "<div class='section-title'>AI Security Explanation</div>" +
        formattedAI;

      // -------------------------
      // Add to history
      // -------------------------
      let historyClass = "history-safe";
      if (data.malicious > 0) historyClass = "history-danger";
      else if (data.suspicious > 0) historyClass = "history-warning";

      scanHistory.unshift({
        filename: data.filename,
        verdict: data.verdict,
        className: historyClass
      });

      renderHistory();   // call AFTER pushing

    } catch (err) {
      aiBox.innerHTML = "<div class='error'><b>Error:</b> " + err + "</div>";
    }
  });


  // -------------------------
  // History renderer (OUTSIDE submit)
  // -------------------------
  function renderHistory() {
    historyList.innerHTML = "";

    for (let i = 0; i < scanHistory.length; i++) {
      let item = scanHistory[i];

      historyList.innerHTML +=
        "<div class='history-item'>" +
          "<div class='history-file'>" + item.filename + "</div>" +
          "<div class='history-verdict " + item.className + "'>" +
            item.verdict +
          "</div>" +
        "</div>";
    }
  }
</script>

</body>
</html>
`)
}
