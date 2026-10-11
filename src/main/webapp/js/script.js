/**
 * Cybersecurity Incident Reporting & Management System (CIRMS)
 * Interactive UI behaviors, real-time risk calculator, table filters & clipboard helpers.
 */

document.addEventListener("DOMContentLoaded", function () {
    initLiveRiskCalculator();
    initTableSearch();
    initPasswordStrength();
    initCopyButtons();
});

/**
 * Live Risk Score Preview on the Incident Report Form
 */
function initLiveRiskCalculator() {
    const categorySelect = document.getElementById("categorySelect");
    const assetInput = document.getElementById("assetInput");
    const scopeSelect = document.getElementById("scopeSelect");
    const sensitivitySelect = document.getElementById("sensitivitySelect");
    const previewScore = document.getElementById("previewRiskScore");
    const previewLevel = document.getElementById("previewRiskLevel");
    const previewBar = document.getElementById("previewRiskBar");

    if (!categorySelect || !previewScore) return;

    function recalculate() {
        const cat = (categorySelect.value || "").toUpperCase();
        const asset = (assetInput ? assetInput.value : "").toLowerCase();
        const scope = (scopeSelect ? scopeSelect.value : "").toUpperCase();
        const sens = (sensitivitySelect ? sensitivitySelect.value : "").toUpperCase();

        // 1. Threat category weight
        let catWeight = 0.50;
        if (cat === "RANSOMWARE") catWeight = 1.0;
        else if (cat === "DATA BREACH") catWeight = 0.95;
        else if (cat === "INSIDER THREAT") catWeight = 0.85;
        else if (cat === "DDOS") catWeight = 0.80;
        else if (cat === "MALWARE") catWeight = 0.75;
        else if (cat === "PHISHING") catWeight = 0.70;
        else if (cat === "UNAUTHORIZED ACCESS") catWeight = 0.65;
        else if (cat === "SOCIAL ENGINEERING") catWeight = 0.60;

        // 2. Asset criticality
        let assetWeight = 0.50;
        if (asset.includes("database") || asset.includes("db") || asset.includes("domain") || 
            asset.includes("nas") || asset.includes("core") || asset.includes("production")) {
            assetWeight = 1.0;
        } else if (asset.includes("payment") || asset.includes("api") || asset.includes("server") || asset.includes("portal")) {
            assetWeight = 0.80;
        } else if (asset.includes("mailbox") || asset.includes("workstation") || asset.includes("laptop")) {
            assetWeight = 0.60;
        } else if (asset.includes("test") || asset.includes("dev")) {
            assetWeight = 0.35;
        }

        // 3. Scope
        let scopeWeight = 0.50;
        if (scope === "ORGANIZATION-WIDE") scopeWeight = 1.0;
        else if (scope === "EXTERNAL/CLIENT") scopeWeight = 0.85;
        else if (scope === "DEPARTMENT") scopeWeight = 0.60;
        else if (scope === "INDIVIDUAL") scopeWeight = 0.30;

        // 4. Sensitivity
        let sensWeight = 0.50;
        if (sens.includes("HIGH") || sens.includes("PII") || sens.includes("CRITICAL")) sensWeight = 1.0;
        else if (sens.includes("CONFIDENTIAL")) sensWeight = 0.80;
        else if (sens.includes("INTERNAL")) sensWeight = 0.50;
        else if (sens.includes("PUBLIC")) sensWeight = 0.20;

        const score = Math.min(100, Math.max(0, Math.round((catWeight * 0.35 + assetWeight * 0.25 + scopeWeight * 0.20 + sensWeight * 0.20) * 100)));

        previewScore.textContent = score;

        let level = "LOW";
        let color = "#38bdf8";
        if (score >= 85) {
            level = "CRITICAL";
            color = "#f43f5e";
        } else if (score >= 65) {
            level = "HIGH";
            color = "#f97316";
        } else if (score >= 40) {
            level = "MEDIUM";
            color = "#f59e0b";
        }

        if (previewLevel) {
            previewLevel.textContent = level;
            previewLevel.style.color = color;
        }
        if (previewBar) {
            previewBar.style.width = score + "%";
            previewBar.style.backgroundColor = color;
        }
    }

    [categorySelect, scopeSelect, sensitivitySelect].forEach(el => {
        if (el) el.addEventListener("change", recalculate);
    });
    if (assetInput) {
        assetInput.addEventListener("input", recalculate);
    }
    recalculate();
}

/**
 * Universal Client-Side Filter for Cyber Tables
 */
function initTableSearch() {
    const searchInputs = document.querySelectorAll("[data-table-search]");
    searchInputs.forEach(input => {
        const targetTableId = input.getAttribute("data-table-search");
        const table = document.getElementById(targetTableId);
        if (!table) return;

        input.addEventListener("input", function () {
            const query = this.value.toLowerCase().trim();
            const rows = table.querySelectorAll("tbody tr");

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(query)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });
    });
}

/**
 * Registration Password Strength Visualizer
 */
function initPasswordStrength() {
    const passwordInput = document.getElementById("regPassword");
    const strengthBar = document.getElementById("passwordStrengthBar");
    const strengthText = document.getElementById("passwordStrengthText");

    if (!passwordInput || !strengthBar) return;

    passwordInput.addEventListener("input", function () {
        const val = this.value;
        let score = 0;
        if (val.length >= 6) score += 25;
        if (val.length >= 10) score += 25;
        if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score += 25;
        if (/[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) score += 25;

        strengthBar.style.width = score + "%";
        if (score <= 25) {
            strengthBar.style.backgroundColor = "#f43f5e";
            if (strengthText) strengthText.textContent = "Weak (Minimum 6 chars)";
        } else if (score <= 50) {
            strengthBar.style.backgroundColor = "#f59e0b";
            if (strengthText) strengthText.textContent = "Moderate";
        } else if (score <= 75) {
            strengthBar.style.backgroundColor = "#38bdf8";
            if (strengthText) strengthText.textContent = "Good";
        } else {
            strengthBar.style.backgroundColor = "#10b981";
            if (strengthText) strengthText.textContent = "Strong Passphrase";
        }
    });
}

/**
 * Copy to Clipboard for IOCs, Hashes and Incident IDs
 */
function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", function () {
            const textToCopy = this.getAttribute("data-copy");
            if (!textToCopy) return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHtml = this.innerHTML;
                this.innerHTML = "✓ Copied";
                setTimeout(() => {
                    this.innerHTML = originalHtml;
                }, 1500);
            });
        });
    });
}

/**
 * Helper to print or export active report view
 */
function printReport() {
    window.print();
}

/**
 * Toggle password visibility
 */
function togglePassVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🔒';
    } else {
        input.type = 'password';
        btn.textContent = '👁️';
    }
}
