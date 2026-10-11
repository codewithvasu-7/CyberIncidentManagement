<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.security.ClientInfoUtil, com.cyberincident.security.CsrfUtil" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null) {
        response.sendRedirect(request.getContextPath() + "/login.jsp");
        return;
    }

    String preTitle = request.getParameter("title") != null ? request.getParameter("title") : "";
    String preCategory = request.getParameter("category") != null ? request.getParameter("category") : "Phishing";
    String preSystem = request.getParameter("affectedSystem") != null ? request.getParameter("affectedSystem") : "";
    String preScope = request.getParameter("impactScope") != null ? request.getParameter("impactScope") : "Individual";
    String preSensitivity = request.getParameter("dataSensitivity") != null ? request.getParameter("dataSensitivity") : "Highly Sensitive / PII";
    String preSeverity = request.getParameter("severity") != null ? request.getParameter("severity") : "";
    String preDescription = request.getParameter("description") != null ? request.getParameter("description") : "";
    String preIoc = request.getParameter("iocIndicators") != null ? request.getParameter("iocIndicators") : (request.getParameter("url") != null ? request.getParameter("url") : "");
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Incident - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .report-layout {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }
        @media (max-width: 900px) {
            .report-layout {
                grid-template-columns: 1fr;
            }
        }
        .form-grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        .risk-preview-box {
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-sm);
            padding: 20px;
            text-align: center;
        }
        .template-toolbar {
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }
    </style>
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">
                    <svg class="icon icon-md" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <span>CIRMS</span>
                <span class="brand-badge">User Desk</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/user/dashboard.jsp">Dashboard</a></li>
                <li>
                    <a href="<%= request.getContextPath() %>/scanner.jsp">
                        <svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                        Threat Scanner
                    </a>
                </li>
                <li><a href="<%= request.getContextPath() %>/user/report.jsp" class="active">+ Report Incident</a></li>
                <li><a href="<%= request.getContextPath() %>/user/incidents.jsp">My Incidents</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge user"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="margin-bottom: 20px;">
            <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">🚨 Register Security Incident / Query</h1>
            <p style="color: var(--text-secondary); font-size: 0.92rem;">
                Submit any security concern or accidental compromise. Our automated CIRMS Forensic Engine will instantly detonate indicators, diagnose what happened to your data, and provide an actionable emergency resolution dossier.
            </p>
        </div>

        <!-- Quick 1-Click Incident Scenario Assistant -->
        <div class="template-toolbar">
            <div>
                <strong style="color: var(--text-primary); font-size: 0.95rem; display: block; margin-bottom: 2px;">⚡ 1-Click Emergency Incident Scenarios</strong>
                <span style="color: var(--text-secondary); font-size: 0.84rem;">Select a scenario to auto-fill details and receive instant forensic investigation:</span>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button type="button" class="btn btn-secondary" onclick="applyMaliciousLinkScenario()" style="font-size: 0.82rem; padding: 7px 12px; display: inline-flex; align-items: center; gap: 6px;">
                    <span>🚨</span>
                    <span>Accidentally Clicked Malicious Link</span>
                </button>
                <button type="button" class="btn btn-secondary" onclick="applyCredentialTheftScenario()" style="font-size: 0.82rem; padding: 7px 12px; display: inline-flex; align-items: center; gap: 6px;">
                    <span>🔑</span>
                    <span>Entered Password / OTP on Fake Page</span>
                </button>
                <button type="button" class="btn btn-secondary" onclick="applyQuishingScenario()" style="font-size: 0.82rem; padding: 7px 12px; display: inline-flex; align-items: center; gap: 6px;">
                    <span>📲</span>
                    <span>Scanned Unknown QR Code</span>
                </button>
            </div>
        </div>

        <% 
            String error = (String) request.getAttribute("error");
            if (error != null) { 
        %>
            <div class="alert alert-danger">
                <span>⚠️</span>
                <span><%= ClientInfoUtil.escapeHtml(error) %></span>
            </div>
        <% } %>

        <div class="report-layout">
            <!-- Form column -->
            <div class="card">
                <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST" id="incidentForm">
                    <input type="hidden" name="action" value="report">
                    <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">

                    <div class="form-group">
                        <label class="form-label" for="title">Incident Title *</label>
                        <input type="text" id="title" name="title" class="form-control" value="<%= ClientInfoUtil.escapeHtml(preTitle) %>" placeholder="Brief summary, e.g., Accidentally opened suspicious link and data fetched" required>
                    </div>

                    <div class="form-grid-2">
                        <div class="form-group">
                            <label class="form-label" for="categorySelect">Threat Category *</label>
                            <select id="categorySelect" name="category" class="form-control" required>
                                <option value="Phishing" <%= "Phishing".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Phishing / Social Engineering</option>
                                <option value="Data Breach" <%= "Data Breach".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Data Breach / Data Fetch / Leak</option>
                                <option value="Malware" <%= "Malware".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Malware / Malicious Script</option>
                                <option value="Unauthorized Access" <%= "Unauthorized Access".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Unauthorized Access / Credential Abuse</option>
                                <option value="Ransomware" <%= "Ransomware".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Ransomware / Encryption</option>
                                <option value="DDoS" <%= "DDoS".equalsIgnoreCase(preCategory) ? "selected" : "" %>>DDoS / Service Disruption</option>
                                <option value="Insider Threat" <%= "Insider Threat".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Insider Threat / Privilege Misuse</option>
                                <option value="Other" <%= "Other".equalsIgnoreCase(preCategory) ? "selected" : "" %>>Other Security Anomaly</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="assetInput">Affected System / Device *</label>
                            <input type="text" id="assetInput" name="affectedSystem" class="form-control" value="<%= ClientInfoUtil.escapeHtml(preSystem) %>" placeholder="e.g. Mobile Device Browser, Workstation WS-04, Personal Gmail Account" required>
                        </div>
                    </div>

                    <div class="form-grid-2">
                        <div class="form-group">
                            <label class="form-label" for="scopeSelect">Estimated Impact Scope</label>
                            <select id="scopeSelect" name="impactScope" class="form-control">
                                <option value="Individual" <%= "Individual".equalsIgnoreCase(preScope) ? "selected" : "" %>>Individual User / Single Device</option>
                                <option value="Department" <%= "Department".equalsIgnoreCase(preScope) ? "selected" : "" %>>Department / Local Subnet</option>
                                <option value="Organization-Wide" <%= "Organization-Wide".equalsIgnoreCase(preScope) ? "selected" : "" %>>Organization-Wide Infrastructure</option>
                                <option value="External/Client" <%= "External/Client".equalsIgnoreCase(preScope) ? "selected" : "" %>>External / Customer Impact</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="sensitivitySelect">Data Sensitivity Classification</label>
                            <select id="sensitivitySelect" name="dataSensitivity" class="form-control">
                                <option value="Highly Sensitive / PII" <%= preSensitivity.contains("PII") ? "selected" : "" %>>Highly Sensitive / PII / Credentials / Bank</option>
                                <option value="Confidential" <%= "Confidential".equalsIgnoreCase(preSensitivity) ? "selected" : "" %>>Confidential / Proprietary</option>
                                <option value="Internal" <%= "Internal".equalsIgnoreCase(preSensitivity) ? "selected" : "" %>>Internal Business Data</option>
                                <option value="Public" <%= "Public".equalsIgnoreCase(preSensitivity) ? "selected" : "" %>>Public / Non-Sensitive</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="severitySelect">Perceived Severity Assessment</label>
                        <select id="severitySelect" name="severity" class="form-control">
                            <option value="">-- Let CIRMS Risk Engine Auto-Calculate --</option>
                            <option value="CRITICAL" <%= "CRITICAL".equalsIgnoreCase(preSeverity) ? "selected" : "" %>>CRITICAL - Compromise of credentials, tokens, or banking data</option>
                            <option value="HIGH" <%= "HIGH".equalsIgnoreCase(preSeverity) ? "selected" : "" %>>HIGH - Malicious link opened, sensitive exposure</option>
                            <option value="MEDIUM" <%= "MEDIUM".equalsIgnoreCase(preSeverity) ? "selected" : "" %>>MEDIUM - Suspicious activity, potential tracking</option>
                            <option value="LOW" <%= "LOW".equalsIgnoreCase(preSeverity) ? "selected" : "" %>>LOW - Minor anomaly, no active compromise</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="description">Detailed Incident Chronology &amp; Description *</label>
                        <textarea id="description" name="description" class="form-control" rows="5" placeholder="Describe exactly what happened: did you receive a message? What link was provided? Did you click or open it? What did the webpage show, and what data (cookies, passwords, phone number, device info) did it appear to access or fetch?" required><%= ClientInfoUtil.escapeHtml(preDescription) %></textarea>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="iocIndicators">Malicious Link / URLs / Indicators of Compromise (IOCs)</label>
                        <textarea id="iocIndicators" name="iocIndicators" class="form-control" rows="3" placeholder="Paste the exact suspicious link, domain or IP (e.g., http://paypa1-security-verify.xyz/account/login.php?user=victim)"><%= ClientInfoUtil.escapeHtml(preIoc) %></textarea>
                        <small style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 4px;">
                            💡 CIRMS will automatically detonate and scan this link to explain what happened to you and what data was exposed.
                        </small>
                    </div>

                    <button type="submit" class="btn btn-primary" style="padding: 12px 24px; font-size: 1rem; width: 100%;">
                        🚀 Submit for Instant Forensic Resolution &amp; Remediation Plan &rarr;
                    </button>
                </form>
            </div>

            <!-- Real-time Quantitative Risk preview sidebar -->
            <div class="card" style="align-self: start;">
                <div class="card-header">
                    <div class="card-title">
                        <span>⚡</span>
                        <span>SOC Risk Score Predictor</span>
                    </div>
                </div>

                <div class="risk-preview-box">
                    <div style="font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px;">
                        Estimated Threat Score
                    </div>
                    <div id="previewRiskScore" style="font-size: 3.5rem; font-weight: 800; font-family: var(--font-mono); color: var(--text-primary); margin: 8px 0;">
                        65
                    </div>
                    <div id="previewRiskLevel" style="font-weight: 800; font-size: 1.1rem; letter-spacing: 1px; color: var(--amber-warning);">
                        HIGH
                    </div>
                    <div style="background: var(--neu-surface); box-shadow: var(--neu-sunken-sm); height: 8px; border-radius: var(--radius-pill); margin-top: 14px; overflow: hidden; border: var(--neu-border-subtle);">
                        <div id="previewRiskBar" style="width: 65%; height: 100%; background: var(--amber-warning); transition: all 0.3s ease;"></div>
                    </div>
                </div>

                <div style="margin-top: 20px; font-size: 0.82rem; color: var(--text-secondary); line-height: 1.6;">
                    <strong style="color: var(--text-primary); display: block; margin-bottom: 6px;">Automated Forensic Diagnostics:</strong>
                    <p style="margin-bottom: 8px;">
                        When you submit, CIRMS triggers the <strong>Incident Forensic Engine</strong> to:
                    </p>
                    <ul style="padding-left: 18px; margin: 0; display: flex; flex-direction: column; gap: 4px;">
                        <li>Detonate reported URLs against typosquatting &amp; phishing heuristics.</li>
                        <li>Examine how the link fetched your device telemetry or session cookies.</li>
                        <li>Generate a step-by-step personal emergency recovery action plan.</li>
                        <li>Produce a printable NIST SP 800-61 Forensic Incident Dossier.</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <jsp:include page="/includes/footer.jsp" />

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
    <script>
        function applyMaliciousLinkScenario() {
            document.getElementById('title').value = "Accidentally Opened Malicious Link - Suspected Data Fetch & Compromise";
            document.getElementById('categorySelect').value = "Phishing";
            document.getElementById('assetInput').value = "User Web Browser & Personal Mobile Device";
            document.getElementById('scopeSelect').value = "Individual";
            document.getElementById('sensitivitySelect').value = "Highly Sensitive / PII";
            document.getElementById('severitySelect').value = "HIGH";
            document.getElementById('description').value = "Someone sent me a message containing a suspicious verification URL. I accidentally clicked and opened the link on my browser. The webpage loaded an unverified portal and appeared to extract my device telemetry, active session cookies, and IP address. Please investigate what happened to my system, determine what data was fetched/compromised, and provide immediate recovery steps.";
            if (!document.getElementById('iocIndicators').value.trim()) {
                document.getElementById('iocIndicators').value = "http://paypa1-security-verify.xyz/account/login.php?user=victim";
            }
            if (typeof updateRiskPreview === 'function') {
                updateRiskPreview();
            }
        }

        function applyCredentialTheftScenario() {
            document.getElementById('title').value = "Fake Login Portal Phish - Password & Session Entered";
            document.getElementById('categorySelect').value = "Unauthorized Access";
            document.getElementById('assetInput').value = "Corporate Workstation & Email Account";
            document.getElementById('scopeSelect').value = "Department";
            document.getElementById('sensitivitySelect').value = "Highly Sensitive / PII";
            document.getElementById('severitySelect').value = "CRITICAL";
            document.getElementById('description').value = "Received an urgent notification claiming my account was suspended. I clicked the link and entered my login username and password on the landing page before realizing the domain was spoofed. The attacker has likely captured my credentials.";
            if (!document.getElementById('iocIndicators').value.trim()) {
                document.getElementById('iocIndicators').value = "http://micros0ft-auth-login.tk/auth/session";
            }
            if (typeof updateRiskPreview === 'function') {
                updateRiskPreview();
            }
        }

        function applyQuishingScenario() {
            document.getElementById('title').value = "Malicious QR Code (Quishing) Scanned on Mobile";
            document.getElementById('categorySelect').value = "Phishing";
            document.getElementById('assetInput').value = "Employee Smartphone Camera & Browser";
            document.getElementById('scopeSelect').value = "Individual";
            document.getElementById('sensitivitySelect').value = "Confidential";
            document.getElementById('severitySelect').value = "HIGH";
            document.getElementById('description').value = "Scanned a QR code on a suspicious notice claiming to be an IT parking/cafeteria pass update. The QR code redirected my browser to a deceptive external site requesting device permissions and session tokens.";
            if (!document.getElementById('iocIndicators').value.trim()) {
                document.getElementById('iocIndicators').value = "http://qr-gateway-portal.top/mobile-auth";
            }
            if (typeof updateRiskPreview === 'function') {
                updateRiskPreview();
            }
        }
    </script>
</body>
</html>
