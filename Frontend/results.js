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
    updateVerdict(verdict, score, data.summary);

    document.getElementById("scanned-url-text").textContent = url;

    updateHybridScores(data);
    updateMLInsights(data.ml_details, data.ml_score);

    renderChecks(checks);

    document.getElementById("checks-count").textContent =
        `${checks.length} check${checks.length === 1 ? "" : "s"}`;
}

/* Update dual-engine breakdown cards */
function updateHybridScores(data) {
    const ruleScore = data.rule_score != null ? Number(data.rule_score) : null;
    const mlScore = data.ml_score != null ? Number(data.ml_score) : null;
    const hybridScore = Number(data.score ?? 0);

    const ruleEl = document.getElementById("rule-score-display");
    const rulePill = document.getElementById("rule-status-pill");
    if (ruleEl) {
        ruleEl.innerHTML = ruleScore != null ? `${ruleScore}<small>/100</small>` : "--";
        if (ruleScore != null) {
            ruleEl.style.color = getScoreColor(ruleScore);
            rulePill.textContent = ruleScore < 30 ? "SAFE" : (ruleScore < 70 ? "WARNING" : "RISK");
            rulePill.style.backgroundColor = getScoreBgColor(ruleScore);
            rulePill.style.color = getScoreColor(ruleScore);
        }
    }

    const mlEl = document.getElementById("ml-score-display");
    const mlPill = document.getElementById("ml-status-pill");
    if (mlEl) {
        mlEl.innerHTML = mlScore != null ? `${mlScore}<small>/100</small>` : "--";
        if (mlScore != null) {
            mlEl.style.color = getScoreColor(mlScore);
            const mlVerdict = data.ml_details?.verdict || (mlScore < 50 ? "LEGITIMATE" : "PHISHING RISK");
            mlPill.textContent = mlVerdict.toUpperCase();
            mlPill.style.backgroundColor = getScoreBgColor(mlScore);
            mlPill.style.color = getScoreColor(mlScore);
        }
    }

    const hybridEl = document.getElementById("hybrid-score-display");
    const hybridPill = document.getElementById("hybrid-status-pill");
    if (hybridEl) {
        hybridEl.innerHTML = `${hybridScore}<small>/100</small>`;
        hybridEl.style.color = getScoreColor(hybridScore);
        if (hybridPill) {
            hybridPill.textContent = data.verdict ? data.verdict.toUpperCase() : "HYBRID BLEND";
            hybridPill.style.backgroundColor = getScoreBgColor(hybridScore);
            hybridPill.style.color = getScoreColor(hybridScore);
        }
    }
}

/* Update ML signals and telemetry badge list */
function updateMLInsights(mlDetails, mlScore) {
    const confidenceEl = document.getElementById("ml-meta-confidence");
    const signalsList = document.getElementById("ml-signals-list");

    if (confidenceEl && mlDetails?.confidence != null) {
        const confPercent = Math.round(mlDetails.confidence * 100);
        confidenceEl.textContent = `Confidence: ${confPercent}%`;
    }

    if (signalsList) {
        signalsList.innerHTML = "";
        const signals = mlDetails?.signals_detected || [];

        if (signals.length === 0) {
            const isSafe = (mlScore == null || mlScore < 50);
            const tag = document.createElement("span");
            tag.className = "ml-signal-tag safe";
            tag.textContent = isSafe 
                ? "✓ No anomalous pattern signals identified" 
                : "Standard structural characteristics";
            signalsList.appendChild(tag);
        } else {
            signals.forEach(function (signal) {
                const tag = document.createElement("span");
                tag.className = "ml-signal-tag warning";
                tag.textContent = `⚡ ${signal}`;
                signalsList.appendChild(tag);
            });
        }
    }
}

/* Get soft background color matching score */
function getScoreBgColor(score) {
    if (score < 30) return "rgba(22, 163, 74, 0.12)";
    if (score < 70) return "rgba(217, 119, 6, 0.12)";
    return "rgba(220, 38, 38, 0.12)";
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
function updateVerdict(verdict, score, summary) {
    const verdictElement = document.getElementById("verdict");
    const descriptionElement =
        document.getElementById("verdict-description");

    verdictElement.textContent = verdict;

    const normalized = verdict.toLowerCase();

    if (summary) {
        descriptionElement.textContent = summary;
    } else if (normalized.includes("low risk")) {
        descriptionElement.textContent =
            "No meaningful URL-level phishing indicators were found.";
    } else if (normalized.includes("caution")) {
        descriptionElement.textContent =
            "Some URL-level signals require caution before proceeding.";
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
                ${check.severity ? ` · ${escapeHtml(check.severity)}` : ""}
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
