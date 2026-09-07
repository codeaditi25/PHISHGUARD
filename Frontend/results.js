/* =========================================================
   LINKSHIELD - RESULTS DISPLAY
   ========================================================= */

/* Render the complete backend response */
function displayResults(data) {
    const score = Number(data.score ?? 0);
    const verdict = data.verdict ?? "Unknown";
    const url = data.url ?? "";
    const checks = data.checks ?? [];

    updateScore(score);
    updateVerdict(verdict, score);

    document.getElementById("scanned-url-text").textContent = url;

    renderChecks(checks);

    document.getElementById("checks-count").textContent =
        `${checks.length} check${checks.length === 1 ? "" : "s"}`;
}

/* Update circular score indicator */
function updateScore(score) {
    const scoreElement = document.getElementById("risk-score");
    const circle = document.getElementById("score-circle");

    const safeScore = Math.min(100, Math.max(0, score));
    scoreElement.textContent = safeScore;

    const degrees = safeScore * 3.6;

    circle.style.background = `
        conic-gradient(
            ${getScoreColor(safeScore)} ${degrees}deg,
            #e9edf3 ${degrees}deg
        )
    `;
}

/* Choose score color based on risk level */
function getScoreColor(score) {
    if (score < 30) return "#16a34a";
    if (score < 70) return "#d97706";
    return "#dc2626";
}

/* Update verdict text */
function updateVerdict(verdict, score) {
    const verdictElement = document.getElementById("verdict");
    const descriptionElement =
        document.getElementById("verdict-description");

    verdictElement.textContent = verdict;

    const normalized = verdict.toLowerCase();

    if (normalized.includes("safe")) {
        descriptionElement.textContent =
            "No significant risk indicators were detected.";
    } else if (
        normalized.includes("suspicious") ||
        normalized.includes("warning")
    ) {
        descriptionElement.textContent =
            "The URL contains characteristics that require caution.";
    } else if (
        normalized.includes("danger") ||
        normalized.includes("malicious") ||
        normalized.includes("phishing")
    ) {
        descriptionElement.textContent =
            "Multiple risk indicators suggest that this URL may be dangerous.";
    } else {
        descriptionElement.textContent =
            `The URL received a risk score of ${score}/100.`;
    }

    verdictElement.style.color = getScoreColor(score);
}

/* Render individual security checks */
function renderChecks(checks) {
    const analysisList = document.getElementById("analysis-list");
    analysisList.innerHTML = "";

    if (!checks.length) {
        analysisList.innerHTML = `
            <div class="analysis-item">
                <div class="check-content">
                    <div class="check-name">No detailed checks available</div>
                    <div class="check-reason">
                        The backend did not return individual analysis results.
                    </div>
                </div>
            </div>
        `;
        return;
    }

    checks.forEach(function (check) {
        analysisList.appendChild(createCheckElement(check));
    });
}

/* Build one security-check row */
function createCheckElement(check) {
    const item = document.createElement("div");
    const status = normalizeStatus(check.status);

    item.className = `analysis-item status-${status}`;

    const icon = getStatusIcon(status);
    const statusText = getStatusText(status);

    // Escape backend values before inserting them into HTML.
    item.innerHTML = `
        <div class="check-icon">${icon}</div>

        <div class="check-content">
            <div class="check-name">
                ${escapeHtml(check.name || "Security Check")}
            </div>
            <div class="check-reason">
                ${escapeHtml(
                    check.reason ||
                    "No additional information provided."
                )}
            </div>
        </div>

        <div class="check-status">${statusText}</div>
    `;

    return item;
}

/* Normalize different backend status names */
function normalizeStatus(status) {
    const value = String(status || "").toLowerCase();

    if (
        value === "safe" ||
        value === "pass" ||
        value === "passed" ||
        value === "clean"
    ) {
        return "safe";
    }

    if (
        value === "danger" ||
        value === "dangerous" ||
        value === "malicious" ||
        value === "fail" ||
        value === "failed"
    ) {
        return "danger";
    }

    return "warning";
}

/* Icons for check results */
function getStatusIcon(status) {
    if (status === "safe") return "✓";
    if (status === "danger") return "!";
    return "⚠";
}

/* Labels for check results */
function getStatusText(status) {
    if (status === "safe") return "PASS";
    if (status === "danger") return "RISK";
    return "WARNING";
}

/* Prevent backend-provided text from becoming executable HTML */
function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value);
    return div.innerHTML;
}
