// Feature descriptions map for the telemetry table
const FEATURE_DESCRIPTIONS = {
    "url_length": "Total character length of the complete URL string.",
    "hostname_length": "Length of the fully qualified domain name (FQDN).",
    "path_length": "Depth and length of resource path segments.",
    "count_dots": "Number of periods in the URL (elevated in subdomain phishing).",
    "count_hyphens": "Number of dashes (frequently used to mimic brand names).",
    "count_at": "Presence of '@' symbol which can redirect traffic to an alternate host.",
    "count_question": "Count of query delimiter symbols.",
    "count_equal": "Count of key-value parameter assignments in query strings.",
    "count_slash": "Directory hierarchy depth delimiters.",
    "count_percent": "Hex URL encoding indicator (often used to obscure attacks).",
    "count_subdomains": "Nesting depth of subdomains (e.g. login.secure.bank.com).",
    "has_ip_address": "Binary flag: 1 if raw IP address is used instead of domain name.",
    "is_https": "Binary flag: 1 if secure TLS/SSL protocol is detected.",
    "has_https_in_hostname": "Detects deceptive 'https' token inside domain labels.",
    "is_shortened": "Binary flag: 1 if domain belongs to a known URL shortener.",
    "digit_ratio": "Ratio of numeric digits to total characters in URL.",
    "letter_ratio": "Ratio of alphabetic characters to total characters in URL.",
    "shannon_entropy": "Information entropy; higher values flag randomized/DGA strings.",
    "suspicious_keyword_count": "Count of credential, banking, or urgent action keywords.",
    "suspicious_tld": "Flag indicating high-abuse Top-Level Domain extension.",
    "has_punycode": "Flag for internationalized domain homograph spoofing (xn--).",
    "consecutive_chars_max": "Longest consecutive sequence of identical characters."
};

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initSingleScan();
    initBatchScan();
    loadFeatureImportances();
});

// Tab navigation
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");

            tabBtns.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}

// Single URL scan
function initSingleScan() {
    const form = document.getElementById("url-form");
    const urlInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scan-btn");
    const btnText = scanBtn.querySelector(".btn-text");
    const spinner = scanBtn.querySelector(".spinner");
    const resultsPanel = document.getElementById("results-panel");

    // Quick test preset buttons
    document.querySelectorAll(".sample-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            urlInput.value = btn.getAttribute("data-url");
            form.dispatchEvent(new Event("submit"));
        });
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        // UI Loading state
        btnText.textContent = "Analyzing...";
        spinner.classList.remove("hidden");
        scanBtn.disabled = true;

        try {
            const response = await fetch("/api/predict", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (data.success && data.data) {
                renderSingleResult(data.data);
                resultsPanel.classList.remove("hidden");
                resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
            } else {
                alert("Scan error: " + (data.error || "Unknown response"));
            }
        } catch (err) {
            console.error("Scan failed:", err);
            alert("Failed to communicate with analysis server.");
        } finally {
            btnText.textContent = "Analyze URL";
            spinner.classList.add("hidden");
            scanBtn.disabled = false;
        }
    });
}

function renderSingleResult(result) {
    const riskScore = result.risk_score;
    const scoreElem = document.getElementById("risk-score-value");
    const gaugeBar = document.getElementById("gauge-bar");
    const verdictBanner = document.getElementById("verdict-banner");
    const verdictLabel = document.getElementById("verdict-label");
    const verdictConf = document.getElementById("verdict-confidence");
    const displayUrl = document.getElementById("display-scanned-url");
    const threatList = document.getElementById("threat-indicators-list");
    const featuresBody = document.getElementById("features-table-body");

    // Display URL
    displayUrl.textContent = result.url;

    // Animate circular gauge
    const circumference = 408.4; // 2 * PI * 65
    const offset = circumference - (riskScore / 100) * circumference;
    gaugeBar.style.strokeDashoffset = offset;
    scoreElem.textContent = `${riskScore}%`;

    // Color and banner states
    verdictBanner.className = "verdict-banner";
    if (riskScore < 35) {
        gaugeBar.style.stroke = "var(--accent-green)";
        verdictBanner.classList.add("safe");
        verdictLabel.textContent = "VERIFIED SAFE / LEGITIMATE";
    } else if (riskScore < 70) {
        gaugeBar.style.stroke = "var(--accent-yellow)";
        verdictBanner.classList.add("warning");
        verdictLabel.textContent = "CAUTION: SUSPICIOUS URL";
    } else {
        gaugeBar.style.stroke = "var(--accent-red)";
        verdictBanner.classList.add("danger");
        verdictLabel.textContent = "CRITICAL PHISHING THREAT";
    }

    verdictConf.textContent = `Confidence: ${(result.confidence * 100).toFixed(1)}% • ${result.risk_level}`;

    // Threat Indicators
    threatList.innerHTML = "";
    if (result.threat_indicators && result.threat_indicators.length > 0) {
        result.threat_indicators.forEach(ind => {
            const li = document.createElement("li");
            li.className = `threat-item ${result.is_phishing ? 'red-flag' : 'green-flag'}`;
            li.innerHTML = `<span>${result.is_phishing ? '⚠️' : '✅'}</span> <span>${ind}</span>`;
            threatList.appendChild(li);
        });
    }

    // 22 Features Table
    featuresBody.innerHTML = "";
    if (result.features) {
        Object.entries(result.features).forEach(([featName, featVal]) => {
            const tr = document.createElement("tr");
            const desc = FEATURE_DESCRIPTIONS[featName] || "Lexical/heuristic structural signal.";
            tr.innerHTML = `
                <td class="feature-name">${featName}</td>
                <td class="feature-val">${featVal}</td>
                <td class="feature-desc">${desc}</td>
            `;
            featuresBody.appendChild(tr);
        });
    }
}

// Batch Scanner
function initBatchScan() {
    const scanBtn = document.getElementById("batch-scan-btn");
    const clearBtn = document.getElementById("batch-clear-btn");
    const exportBtn = document.getElementById("export-csv-btn");
    const textarea = document.getElementById("batch-urls-input");
    const statsContainer = document.getElementById("batch-stats");
    const tableContainer = document.getElementById("batch-results-container");
    const tbody = document.getElementById("batch-table-body");

    let lastBatchResults = [];

    clearBtn.addEventListener("click", () => {
        textarea.value = "";
        statsContainer.classList.add("hidden");
        tableContainer.classList.add("hidden");
        exportBtn.classList.add("hidden");
        lastBatchResults = [];
    });

    scanBtn.addEventListener("click", async () => {
        const lines = textarea.value.split("\n").map(l => l.trim()).filter(l => l.length > 0);
        if (lines.length === 0) {
            alert("Please enter at least one URL to scan.");
            return;
        }

        const btnText = scanBtn.querySelector(".btn-text");
        const spinner = scanBtn.querySelector(".spinner");
        btnText.textContent = `Scanning (${lines.length})...`;
        spinner.classList.remove("hidden");
        scanBtn.disabled = true;

        try {
            const response = await fetch("/api/batch", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ urls: lines })
            });

            const data = await response.json();
            if (data.success) {
                lastBatchResults = data.results;

                // Update summary stats
                document.getElementById("stat-total").textContent = data.summary.total_scanned;
                document.getElementById("stat-phish").textContent = data.summary.phishing_detected;
                document.getElementById("stat-safe").textContent = data.summary.legitimate_verified;
                document.getElementById("stat-ratio").textContent = `${data.summary.threat_percentage}%`;

                // Render Table rows
                tbody.innerHTML = "";
                data.results.forEach((r, idx) => {
                    const tr = document.createElement("tr");
                    const pillClass = r.is_phishing ? "danger" : "safe";
                    const topIndicator = (r.threat_indicators && r.threat_indicators[0]) ? r.threat_indicators[0] : "None";

                    tr.innerHTML = `
                        <td>${idx + 1}</td>
                        <td><code>${r.url}</code></td>
                        <td><span class="tag-pill ${pillClass}">${r.label}</span></td>
                        <td><strong>${r.risk_score}%</strong></td>
                        <td>${(r.confidence * 100).toFixed(1)}%</td>
                        <td style="font-size: 0.78rem; color: var(--text-secondary);">${topIndicator}</td>
                    `;
                    tbody.appendChild(tr);
                });

                statsContainer.classList.remove("hidden");
                tableContainer.classList.remove("hidden");
                exportBtn.classList.remove("hidden");
            }
        } catch (err) {
            console.error("Batch scan error:", err);
            alert("Batch scan request failed.");
        } finally {
            btnText.textContent = "Scan All URLs";
            spinner.classList.add("hidden");
            scanBtn.disabled = false;
        }
    });

    // CSV Export
    exportBtn.addEventListener("click", () => {
        if (!lastBatchResults.length) return;
        let csvContent = "data:text/csv;charset=utf-8,URL,Label,RiskScore,Confidence,RiskLevel\n";
        lastBatchResults.forEach(r => {
            csvContent += `"${r.url}","${r.label}",${r.risk_score},${r.confidence},"${r.risk_level}"\n`;
        });
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `phishguard_batch_results_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });
}

// Load ML Feature Importances for Tab 3
async function loadFeatureImportances() {
    const container = document.getElementById("feature-importance-bars");
    if (!container) return;

    try {
        const response = await fetch("/api/features");
        const data = await response.json();
        if (data.success && data.features) {
            container.innerHTML = "";
            data.features.slice(0, 10).forEach(item => {
                const pct = (item.importance * 100).toFixed(1);
                const row = document.createElement("div");
                row.className = "imp-row";
                row.innerHTML = `
                    <span class="imp-name">${item.feature}</span>
                    <div class="imp-track">
                        <div class="imp-fill" style="width: ${Math.max(5, pct * 2.5)}%;"></div>
                    </div>
                    <span class="imp-pct">${pct}%</span>
                `;
                container.appendChild(row);
            });
        }
    } catch (err) {
        console.warn("Could not load feature importances:", err);
    }
}

// Copy to clipboard helper
function copyCode(elementId) {
    const text = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert("Copied to clipboard!");
    });
}
