const HISTORY_KEY = "portproof-scan-history";
const BASELINE_KEY = "portproof-exposure-baseline";
const ASSESSMENTS_KEY = "portproof-analyst-assessments";

const state = {
  currentResults: null,
  networkInfo: null,
  findingSearch: "",
  severityFilter: "all",
  history: JSON.parse(localStorage.getItem(HISTORY_KEY)) || [],
  baseline: JSON.parse(localStorage.getItem(BASELINE_KEY)) || null,
  assessments:
    JSON.parse(localStorage.getItem(ASSESSMENTS_KEY)) || {}
};

const elements = {
  scanForm: document.querySelector("#scanForm"),
  targetInput: document.querySelector("#targetInput"),
  profileSelect: document.querySelector("#profileSelect"),
  timeoutSelect: document.querySelector("#timeoutSelect"),
  customPortsField: document.querySelector("#customPortsField"),
  customPortsInput: document.querySelector("#customPortsInput"),
  authorisedCheckbox: document.querySelector("#authorisedCheckbox"),
  formMessage: document.querySelector("#formMessage"),
  scanButton: document.querySelector("#scanButton"),
  progressCard: document.querySelector("#progressCard"),
  progressFill: document.querySelector("#progressFill"),
  progressTitle: document.querySelector("#progressTitle"),
  progressMessage: document.querySelector("#progressMessage"),
  elapsedTime: document.querySelector("#elapsedTime"),
  resultsSection: document.querySelector("#resultsSection"),
  findingsTableBody: document.querySelector("#findingsTableBody"),
  emptyFindings: document.querySelector("#emptyFindings"),
  findingSearch: document.querySelector("#findingSearch"),
  severityFilter: document.querySelector("#severityFilter"),
  historyList: document.querySelector("#historyList"),
  saveBaselineButton: document.querySelector("#saveBaselineBtn"),
  clearBaselineButton: document.querySelector("#clearBaselineBtn"),
  baselineComparison: document.querySelector("#baselineComparison"),
  baselineMetadata: document.querySelector("#baselineMetadata"),
  newExposureCount: document.querySelector("#newExposureCount"),
  resolvedExposureCount: document.querySelector("#resolvedExposureCount"),
  unchangedExposureCount: document.querySelector("#unchangedExposureCount"),
  comparisonDetails: document.querySelector("#comparisonDetails")
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadNetworkInfo() {
  try {
    const response = await fetch("/api/network-info");
    const data = await response.json();

    state.networkInfo = data;

    document.querySelector("#localHostname").textContent =
      data.hostname;

    document.querySelector("#localIp").textContent =
      data.local_ip;
  } catch {
    document.querySelector("#localHostname").textContent =
      "Unavailable";

    document.querySelector("#localIp").textContent =
      "Unavailable";
  }
}

function getVisibleFindings() {
  if (!state.currentResults) {
    return [];
  }

  return state.currentResults.findings.filter((finding) => {
    const searchableText = [
      finding.host,
      finding.port,
      finding.service,
      finding.severity,
      finding.explanation,
      finding.remediation
    ]
      .join(" ")
      .toLowerCase();

    const matchesSearch = searchableText.includes(
      state.findingSearch
    );

    const matchesSeverity =
      state.severityFilter === "all" ||
      finding.severity === state.severityFilter;

    return matchesSearch && matchesSeverity;
  });
}

function assessmentKey(finding) {
  return `${state.currentResults.target}|${finding.host}:${finding.port}`;
}

function getAssessment(finding) {
  return state.assessments[assessmentKey(finding)] || {
    decision: "unreviewed",
    note: ""
  };
}

function saveAssessments() {
  localStorage.setItem(
    ASSESSMENTS_KEY,
    JSON.stringify(state.assessments)
  );
}

function renderFindings() {
  const findings = getVisibleFindings();

  elements.emptyFindings.classList.toggle(
    "hidden",
    findings.length > 0
  );

  elements.findingsTableBody.innerHTML = findings
    .map((finding) => {
      const key = assessmentKey(finding);
      const assessment = getAssessment(finding);

      return `
        <tr>
          <td><code>${escapeHtml(finding.host)}</code></td>
          <td><strong>${escapeHtml(finding.port)}</strong></td>
          <td>
            ${escapeHtml(finding.service)}
            <small class="service-confidence">
              ${escapeHtml(finding.service_confidence || "Port-based inference")}
            </small>
          </td>
          <td>
            <span class="severity-badge severity-${escapeHtml(
              finding.severity
            )}">
              ${escapeHtml(finding.severity)}
            </span>
          </td>
          <td>${escapeHtml(finding.response_ms)} ms</td>
          <td>${escapeHtml(finding.explanation)}</td>
          <td>${escapeHtml(finding.remediation)}</td>
          <td>
            <select
              class="analyst-decision"
              data-assessment-key="${escapeHtml(key)}"
            >
              <option value="unreviewed" ${
                assessment.decision === "unreviewed" ? "selected" : ""
              }>Unreviewed</option>
              <option value="investigate" ${
                assessment.decision === "investigate" ? "selected" : ""
              }>Investigate</option>
              <option value="accepted-risk" ${
                assessment.decision === "accepted-risk" ? "selected" : ""
              }>Accepted risk</option>
              <option value="false-positive" ${
                assessment.decision === "false-positive" ? "selected" : ""
              }>False positive</option>
              <option value="remediated" ${
                assessment.decision === "remediated" ? "selected" : ""
              }>Remediated</option>
            </select>
          </td>
          <td>
            <input
              class="analyst-note"
              type="text"
              data-assessment-key="${escapeHtml(key)}"
              value="${escapeHtml(assessment.note)}"
              placeholder="Add investigation note..."
            >
          </td>
        </tr>
      `;
    })
    .join("");
}

function findingKey(finding) {
  return `${finding.host}:${finding.port}`;
}

function createBaseline(results) {
  return {
    scan_id: results.scan_id,
    target: results.target,
    completed_at: results.completed_at,
    findings: results.findings.map((finding) => ({
      host: finding.host,
      port: finding.port,
      service: finding.service,
      severity: finding.severity
    }))
  };
}

function renderComparisonRows(changes) {
  if (!changes.length) {
    elements.comparisonDetails.innerHTML = `
      <div class="comparison-empty">
        No exposure changes were detected against this baseline.
      </div>
    `;
    return;
  }

  elements.comparisonDetails.innerHTML = changes
    .map(
      ({ finding, status }) => `
        <div class="comparison-detail">
          <div>
            <strong>
              ${escapeHtml(finding.host)}:${escapeHtml(finding.port)}
            </strong>
            <small>${escapeHtml(finding.service)}</small>
          </div>

          <span class="change-badge ${escapeHtml(status)}">
            ${escapeHtml(status)}
          </span>
        </div>
      `
    )
    .join("");
}

function renderBaselineComparison() {
  const baseline = state.baseline;
  const current = state.currentResults;

  if (!baseline || !current) {
    elements.baselineComparison.hidden = true;
    return;
  }

  elements.baselineComparison.hidden = false;

  if (baseline.target !== current.target) {
    elements.baselineMetadata.textContent =
      `The saved baseline covers ${baseline.target}. ` +
      `Scan that same target to calculate exposure changes.`;

    elements.newExposureCount.textContent = "—";
    elements.resolvedExposureCount.textContent = "—";
    elements.unchangedExposureCount.textContent = "—";

    elements.comparisonDetails.innerHTML = `
      <div class="comparison-empty">
        Comparison paused because the current scan and baseline
        targets are different.
      </div>
    `;
    return;
  }

  const baselineMap = new Map(
    baseline.findings.map((finding) => [
      findingKey(finding),
      finding
    ])
  );

  const currentMap = new Map(
    current.findings.map((finding) => [
      findingKey(finding),
      finding
    ])
  );

  const newExposures = current.findings.filter(
    (finding) => !baselineMap.has(findingKey(finding))
  );

  const resolvedExposures = baseline.findings.filter(
    (finding) => !currentMap.has(findingKey(finding))
  );

  const unchangedExposures = current.findings.filter(
    (finding) => baselineMap.has(findingKey(finding))
  );

  elements.baselineMetadata.textContent =
    `Compared with ${baseline.scan_id}, saved ` +
    `${new Date(baseline.completed_at).toLocaleString()}, ` +
    `for ${baseline.target}.`;

  elements.newExposureCount.textContent = newExposures.length;
  elements.resolvedExposureCount.textContent =
    resolvedExposures.length;
  elements.unchangedExposureCount.textContent =
    unchangedExposures.length;

  const changes = [
    ...newExposures.map((finding) => ({
      finding,
      status: "new"
    })),
    ...resolvedExposures.map((finding) => ({
      finding,
      status: "resolved"
    }))
  ];

  renderComparisonRows(changes);
}

function saveCurrentAsBaseline() {
  if (!state.currentResults) {
    return;
  }

  state.baseline = createBaseline(state.currentResults);

  localStorage.setItem(
    BASELINE_KEY,
    JSON.stringify(state.baseline)
  );

  renderBaselineComparison();

  const originalLabel = elements.saveBaselineButton.textContent;
  elements.saveBaselineButton.textContent = "Baseline saved";

  window.setTimeout(() => {
    elements.saveBaselineButton.textContent = originalLabel;
  }, 1600);
}

function clearBaseline() {
  state.baseline = null;
  localStorage.removeItem(BASELINE_KEY);
  elements.baselineComparison.hidden = true;
}

function renderResults(results) {
  state.currentResults = results;
  state.findingSearch = "";
  state.severityFilter = "all";

  elements.findingSearch.value = "";
  elements.severityFilter.value = "all";

  document.querySelector("#hostsChecked").textContent =
    results.hosts_checked;

  document.querySelector("#hostsDiscovered").textContent =
    results.hosts_with_open_ports;

  document.querySelector("#openPortCount").textContent =
    results.open_port_count;

  document.querySelector("#highExposureCount").textContent =
    results.severity_counts.high;

  document.querySelector("#scanSummary").textContent =
    `${results.scan_id} · ${results.target} · ${
      results.duration_seconds
    } seconds · ${
      results.total_connection_checks
    } connection checks`;

  renderFindings();
  renderBaselineComparison();

  elements.resultsSection.classList.remove("hidden");
  elements.resultsSection.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
}

function saveHistory(results) {
  const summary = {
    scan_id: results.scan_id,
    target: results.target,
    completed_at: results.completed_at,
    hosts_checked: results.hosts_checked,
    hosts_discovered: results.hosts_with_open_ports,
    open_ports: results.open_port_count,
    high_exposure: results.severity_counts.high,
    duration_seconds: results.duration_seconds
  };

  state.history = [
    summary,
    ...state.history.filter(
      (item) => item.scan_id !== summary.scan_id
    )
  ].slice(0, 20);

  localStorage.setItem(
    HISTORY_KEY,
    JSON.stringify(state.history)
  );

  renderHistory();
}

function renderHistory() {
  if (!state.history.length) {
    elements.historyList.innerHTML = `
      <div class="history-empty">
        No completed scans are stored yet. Run an authorised scan to
        create the first local history record.
      </div>
    `;
    return;
  }

  elements.historyList.innerHTML = state.history
    .map(
      (item) => `
        <article class="history-item">
          <div class="history-main">
            <strong>${escapeHtml(item.target)}</strong>
            <small>
              ${escapeHtml(item.scan_id)} ·
              ${new Date(item.completed_at).toLocaleString()}
            </small>
          </div>

          <div class="history-stat">
            <span>Hosts checked</span>
            <strong>${escapeHtml(item.hosts_checked)}</strong>
          </div>

          <div class="history-stat">
            <span>Hosts discovered</span>
            <strong>${escapeHtml(item.hosts_discovered)}</strong>
          </div>

          <div class="history-stat">
            <span>Open ports</span>
            <strong>${escapeHtml(item.open_ports)}</strong>
          </div>

          <div class="history-stat">
            <span>High exposure</span>
            <strong>${escapeHtml(item.high_exposure)}</strong>
          </div>
        </article>
      `
    )
    .join("");
}

function startProgressTimer() {
  const startedAt = Date.now();
  let progress = 4;

  elements.progressFill.style.width = `${progress}%`;
  elements.progressCard.classList.remove("hidden");

  const messages = [
    "Validating private target and authorisation...",
    "Preparing TCP connection checks...",
    "Checking authorised hosts and ports...",
    "Classifying reachable services...",
    "Building the exposure assessment..."
  ];

  let messageIndex = 0;

  const interval = window.setInterval(() => {
    const elapsedSeconds = Math.floor(
      (Date.now() - startedAt) / 1000
    );

    elements.elapsedTime.textContent = `${elapsedSeconds}s`;

    progress = Math.min(
      92,
      progress + Math.max(1, Math.round((94 - progress) / 12))
    );

    elements.progressFill.style.width = `${progress}%`;

    if (elapsedSeconds > 0 && elapsedSeconds % 3 === 0) {
      messageIndex = Math.min(
        messages.length - 1,
        messageIndex + 1
      );

      elements.progressMessage.textContent =
        messages[messageIndex];
    }
  }, 500);

  return interval;
}

function downloadFile(filename, content, type) {
  const file = new Blob([content], { type });
  const url = URL.createObjectURL(file);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportJson() {
  if (!state.currentResults) {
    return;
  }

  downloadFile(
    `${state.currentResults.scan_id}.json`,
    JSON.stringify(state.currentResults, null, 2),
    "application/json"
  );
}

function csvCell(value) {
  const escapedValue = String(value).replaceAll('"', '""');
  return `"${escapedValue}"`;
}

function exportCsv() {
  if (!state.currentResults) {
    return;
  }

  const headings = [
    "Scan ID",
    "Target",
    "Host",
    "Port",
    "Likely Service",
    "Severity",
    "Response Time (ms)",
    "Risk Context",
    "Recommended Action",
    "Service Confidence"
  ];

  const rows = state.currentResults.findings.map((finding) => [
    state.currentResults.scan_id,
    state.currentResults.target,
    finding.host,
    finding.port,
    finding.service,
    finding.severity,
    finding.response_ms,
    finding.explanation,
    finding.remediation,
    finding.service_confidence
  ]);

  const csv = [
    headings.map(csvCell).join(","),
    ...rows.map((row) => row.map(csvCell).join(","))
  ].join("\n");

  downloadFile(
    `${state.currentResults.scan_id}.csv`,
    csv,
    "text/csv"
  );
}

function formatDecision(value) {
  const labels = {
    unreviewed: "Unreviewed",
    investigate: "Investigate",
    "accepted-risk": "Accepted risk",
    "false-positive": "False positive",
    remediated: "Remediated"
  };

  return labels[value] || "Unreviewed";
}

function getReportComparison() {
  if (
    !state.baseline ||
    !state.currentResults ||
    state.baseline.target !== state.currentResults.target
  ) {
    return null;
  }

  const baselineKeys = new Set(
    state.baseline.findings.map(findingKey)
  );

  const currentKeys = new Set(
    state.currentResults.findings.map(findingKey)
  );

  return {
    newCount: state.currentResults.findings.filter(
      (finding) => !baselineKeys.has(findingKey(finding))
    ).length,
    resolvedCount: state.baseline.findings.filter(
      (finding) => !currentKeys.has(findingKey(finding))
    ).length,
    unchangedCount: state.currentResults.findings.filter(
      (finding) => baselineKeys.has(findingKey(finding))
    ).length
  };
}

function generateReport() {
  if (!state.currentResults) {
    return;
  }

  const results = state.currentResults;
  const comparison = getReportComparison();
  const generatedAt = new Date().toLocaleString();

  const findingsRows = results.findings
    .map((finding) => {
      const assessment = getAssessment(finding);

      return `
        <tr>
          <td>${escapeHtml(finding.host)}</td>
          <td>${escapeHtml(finding.port)}</td>
          <td>
            <strong>${escapeHtml(finding.service)}</strong>
            <small>${escapeHtml(finding.service_confidence)}</small>
          </td>
          <td>
            <span class="severity ${escapeHtml(finding.severity)}">
              ${escapeHtml(finding.severity)}
            </span>
          </td>
          <td>${escapeHtml(finding.explanation)}</td>
          <td>${escapeHtml(finding.remediation)}</td>
          <td>${escapeHtml(formatDecision(assessment.decision))}</td>
          <td>${escapeHtml(assessment.note || "No analyst note recorded.")}</td>
        </tr>
      `;
    })
    .join("");

  const baselineSection = comparison
    ? `
      <section>
        <h2>Baseline comparison</h2>
        <p>
          Compared with baseline ${escapeHtml(state.baseline.scan_id)},
          captured ${escapeHtml(
            new Date(state.baseline.completed_at).toLocaleString()
          )}.
        </p>
        <div class="metrics three">
          <div><span>New exposures</span><strong>${comparison.newCount}</strong></div>
          <div><span>Resolved exposures</span><strong>${comparison.resolvedCount}</strong></div>
          <div><span>Unchanged</span><strong>${comparison.unchangedCount}</strong></div>
        </div>
      </section>
    `
    : `
      <section>
        <h2>Baseline comparison</h2>
        <p>No matching baseline was available for this target.</p>
      </section>
    `;

  const reportWindow = window.open("", "_blank");

  if (!reportWindow) {
    window.alert(
      "Allow pop-ups for PortProof to generate the assessment report."
    );
    return;
  }

  reportWindow.document.write(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${escapeHtml(results.scan_id)} | PortProof Report</title>
        <style>
          :root {
            color: #172033;
            font-family: Arial, Helvetica, sans-serif;
          }

          * { box-sizing: border-box; }
          body { margin: 0; background: #eef2f7; }
          .report { max-width: 1180px; margin: 24px auto; padding: 42px; background: white; }
          header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 3px solid #20a9d8; padding-bottom: 22px; }
          .brand { color: #087ca7; font-size: 14px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
          h1 { margin: 8px 0; font-size: 32px; }
          h2 { margin: 0 0 12px; font-size: 20px; }
          p { color: #536076; line-height: 1.6; }
          .meta { text-align: right; font-size: 13px; color: #667085; }
          section { margin-top: 30px; }
          .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
          .metrics.three { grid-template-columns: repeat(3, 1fr); }
          .metrics div { padding: 16px; border: 1px solid #d8e0ea; border-radius: 10px; }
          .metrics span { display: block; color: #667085; font-size: 11px; font-weight: 700; text-transform: uppercase; }
          .metrics strong { display: block; margin-top: 7px; font-size: 25px; }
          .scope { padding: 16px; border-left: 4px solid #20a9d8; background: #f5f9fc; }
          table { width: 100%; border-collapse: collapse; font-size: 11px; }
          th { padding: 10px 8px; background: #172033; color: white; text-align: left; }
          td { padding: 10px 8px; border-bottom: 1px solid #dfe5ed; vertical-align: top; line-height: 1.45; }
          td small { display: block; margin-top: 4px; color: #667085; }
          .severity { font-size: 9px; font-weight: 800; text-transform: uppercase; }
          .severity.high { color: #c51f45; }
          .severity.medium { color: #a96000; }
          .severity.low { color: #087ca7; }
          .severity.informational { color: #5865c7; }
          .limitation { padding: 16px; border: 1px solid #e8c474; background: #fffaf0; }
          footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid #d8e0ea; color: #667085; font-size: 11px; }

          @media print {
            body { background: white; }
            .report { max-width: none; margin: 0; padding: 12mm; }
            section, tr { break-inside: avoid; }
            @page { size: landscape; margin: 8mm; }
          }
        </style>
      </head>

      <body>
        <main class="report">
          <header>
            <div>
              <div class="brand">PortProof Defensive Assessment</div>
              <h1>Local Network Exposure Report</h1>
              <p>Authorised TCP exposure assessment and analyst triage record.</p>
            </div>

            <div class="meta">
              <strong>${escapeHtml(results.scan_id)}</strong><br>
              Generated: ${escapeHtml(generatedAt)}<br>
              Scan completed: ${escapeHtml(
                new Date(results.completed_at).toLocaleString()
              )}
            </div>
          </header>

          <section>
            <h2>Executive summary</h2>
            <p>
              PortProof assessed ${escapeHtml(results.hosts_checked)} authorised
              host address(es) within ${escapeHtml(results.target)} and observed
              ${escapeHtml(results.open_port_count)} open TCP port(s).
              ${escapeHtml(results.severity_counts.high)} finding(s) were
              prioritised as high exposure for analyst review. Severity reflects
              exposure context, not confirmation of a vulnerability.
            </p>
          </section>

          <section>
            <h2>Assessment scope</h2>
            <div class="scope">
              <strong>Target:</strong> ${escapeHtml(results.target)}<br>
              <strong>Connection checks:</strong>
              ${escapeHtml(results.total_connection_checks)}<br>
              <strong>Duration:</strong> ${escapeHtml(results.duration_seconds)} seconds<br>
              <strong>Authorisation:</strong> The operator confirmed ownership or
              permission in the PortProof interface before execution.
            </div>
          </section>

          <section>
            <h2>Exposure summary</h2>
            <div class="metrics">
              <div><span>Hosts checked</span><strong>${escapeHtml(results.hosts_checked)}</strong></div>
              <div><span>Hosts discovered</span><strong>${escapeHtml(results.hosts_with_open_ports)}</strong></div>
              <div><span>Open ports</span><strong>${escapeHtml(results.open_port_count)}</strong></div>
              <div><span>High exposure</span><strong>${escapeHtml(results.severity_counts.high)}</strong></div>
            </div>
          </section>

          ${baselineSection}

          <section>
            <h2>Findings and analyst assessment</h2>
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Likely service</th>
                  <th>Severity</th>
                  <th>Risk context</th>
                  <th>Recommended action</th>
                  <th>Decision</th>
                  <th>Analyst note</th>
                </tr>
              </thead>
              <tbody>${findingsRows}</tbody>
            </table>
          </section>

          <section class="limitation">
            <h2>Evidence limitations</h2>
            <p>
              An open port confirms that a TCP connection was accepted. PortProof
              infers likely services from standard port assignments and does not
              independently confirm the listening application, version,
              vulnerability, misconfiguration, exploitation, or malicious activity.
              Findings require validation before operational action is taken.
            </p>
          </section>

          <footer>
            Generated locally by PortProof. Target information was not submitted
            to an external scanning service.
          </footer>
        </main>
      </body>
    </html>
  `);

  reportWindow.document.close();
  reportWindow.focus();

  window.setTimeout(() => {
    reportWindow.print();
  }, 400);
}

elements.findingsTableBody.addEventListener("change", (event) => {
  if (!event.target.matches(".analyst-decision")) {
    return;
  }

  const key = event.target.dataset.assessmentKey;
  const existing = state.assessments[key] || { note: "" };

  state.assessments[key] = {
    ...existing,
    decision: event.target.value
  };

  saveAssessments();
});

elements.findingsTableBody.addEventListener("input", (event) => {
  if (!event.target.matches(".analyst-note")) {
    return;
  }

  const key = event.target.dataset.assessmentKey;
  const existing = state.assessments[key] || {
    decision: "unreviewed"
  };

  state.assessments[key] = {
    ...existing,
    note: event.target.value
  };

  saveAssessments();
});

elements.profileSelect.addEventListener("change", () => {
  const usesCustomPorts =
    elements.profileSelect.value === "custom";

  elements.customPortsField.classList.toggle(
    "hidden",
    !usesCustomPorts
  );

  elements.customPortsInput.required = usesCustomPorts;
});

document
  .querySelector("#useLocalIpButton")
  .addEventListener("click", () => {
    if (
      state.networkInfo &&
      state.networkInfo.local_ip !== "Unavailable"
    ) {
      elements.targetInput.value =
        state.networkInfo.local_ip;
    }
  });

elements.scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  elements.formMessage.classList.add("hidden");

  if (!elements.authorisedCheckbox.checked) {
    elements.formMessage.textContent =
      "Confirm that you own or are authorised to scan the target.";

    elements.formMessage.classList.remove("hidden");
    return;
  }

  const payload = {
    target: elements.targetInput.value.trim(),
    profile: elements.profileSelect.value,
    custom_ports: elements.customPortsInput.value.trim(),
    timeout: Number(elements.timeoutSelect.value),
    authorised: true
  };

  elements.scanButton.disabled = true;
  elements.scanButton.textContent = "Scanning...";
  elements.resultsSection.classList.add("hidden");

  const progressTimer = startProgressTimer();

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.error || "The scan could not be completed."
      );
    }

    elements.progressFill.style.width = "100%";
    elements.progressTitle.textContent = "Scan completed";
    elements.progressMessage.textContent =
      "Exposure assessment generated successfully.";

    renderResults(data);
    saveHistory(data);
  } catch (error) {
    elements.formMessage.textContent = error.message;
    elements.formMessage.classList.remove("hidden");

    elements.progressTitle.textContent = "Scan stopped";
    elements.progressMessage.textContent =
      "No unauthorised or invalid target was scanned.";
  } finally {
    window.clearInterval(progressTimer);

    elements.scanButton.disabled = false;
    elements.scanButton.textContent = "Start authorised scan";

    window.setTimeout(() => {
      elements.progressCard.classList.add("hidden");
      elements.progressTitle.textContent =
        "Checking authorised target";
      elements.progressMessage.textContent =
        "Validating target and preparing connection checks...";
      elements.progressFill.style.width = "4%";
      elements.elapsedTime.textContent = "0s";
    }, 1000);
  }
});

elements.findingSearch.addEventListener("input", (event) => {
  state.findingSearch = event.target.value
    .trim()
    .toLowerCase();

  renderFindings();
});

elements.severityFilter.addEventListener(
  "change",
  (event) => {
    state.severityFilter = event.target.value;
    renderFindings();
  }
);

document
  .querySelector("#exportJsonButton")
  .addEventListener("click", exportJson);

document
  .querySelector("#exportCsvButton")
  .addEventListener("click", exportCsv);

document
  .querySelector("#printReportButton")
  .addEventListener("click", generateReport);

elements.saveBaselineButton.addEventListener(
  "click",
  saveCurrentAsBaseline
);

elements.clearBaselineButton.addEventListener(
  "click",
  clearBaseline
);

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(
      (navItem) => {
        navItem.classList.remove("active");
      }
    );

    button.classList.add("active");

    document.querySelectorAll(".view").forEach((view) => {
      view.classList.remove("active");
    });

    document
      .querySelector(`#${button.dataset.view}View`)
      .classList.add("active");

    if (button.dataset.view === "history") {
      renderHistory();
    }
  });
});

document
  .querySelector("#clearHistoryButton")
  .addEventListener("click", () => {
    state.history = [];
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

loadNetworkInfo();
renderHistory();
