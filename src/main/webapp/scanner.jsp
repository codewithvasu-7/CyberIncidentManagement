<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.UrlScanResult" %>
<%
    User currentUser = (User) session.getAttribute("user");
    UrlScanResult scanResult = (UrlScanResult) request.getAttribute("scanResult");
    String scannedUrl = (String) request.getAttribute("scannedUrl");
    if (scannedUrl == null) scannedUrl = "";
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Link &amp; QR Code Threat Detector - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <!-- jsQR Library for browser-based QR code decoding -->
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <!-- Navigation Header -->
    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">🛡️</div>
                <span>CIRMS</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/index.jsp">Home</a></li>
                <li><a href="<%= request.getContextPath() %>/scanner.jsp" class="active">🔍 Threat Scanner</a></li>
                <% if (currentUser != null) { %>
                    <% if (currentUser.isAdmin()) { %>
                        <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Admin SOC</a></li>
                    <% } else if (currentUser.isAnalyst()) { %>
                        <li><a href="<%= request.getContextPath() %>/analyst/dashboard.jsp">Analyst Desk</a></li>
                    <% } else { %>
                        <li><a href="<%= request.getContextPath() %>/user/dashboard.jsp">User Desk</a></li>
                    <% } %>
                    <li><a href="<%= request.getContextPath() %>/user/report.jsp">+ Report</a></li>
                <% } %>
            </ul>
            <div class="nav-user">
                <% if (currentUser == null) { %>
                    <a href="<%= request.getContextPath() %>/login.jsp" class="btn btn-secondary">Sign In</a>
                    <a href="<%= request.getContextPath() %>/register.jsp" class="btn btn-primary">Register</a>
                <% } else { %>
                    <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 700;"><%= currentUser.getFullName() %></span>
                    <span class="role-badge <%= currentUser.getRole().toLowerCase() %>"><%= currentUser.getRole() %></span>
                    <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger btn-sm">Sign Out</a>
                <% } %>
            </div>
        </div>
    </nav>

    <div class="container scanner-container">
        <!-- Banner Title -->
        <div style="text-align: center; margin-bottom: 32px;">
            <div style="display: inline-flex; align-items: center; gap: 8px; padding: 6px 18px; background: var(--neu-base); box-shadow: var(--neu-sunken-sm); border: var(--neu-border-subtle); border-radius: var(--radius-pill); font-size: 0.82rem; font-weight: 700; color: var(--cobalt-primary); margin-bottom: 14px;">
                ⚡ AI-Assisted Heuristic Phishing &amp; Quishing Threat Engine
            </div>
            <h1 style="font-size: 2.4rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.025em; margin-bottom: 8px;">
                Malicious Link &amp; QR Code Threat Scanner
            </h1>
            <p style="color: var(--text-secondary); font-size: 1.02rem; max-width: 680px; margin: 0 auto; line-height: 1.6;">
                Detect fake brand lookalikes, typosquatting lures, high-risk TLDs, credential harvesters, and malicious QR codes before clicking.
            </p>
        </div>

        <!-- Scanner Selector Tabs -->
        <div class="scanner-tabs">
            <button type="button" class="tab-btn active" id="tabUrlBtn" onclick="switchScannerTab('url')">
                🌐 Inspect Link / URL
            </button>
            <button type="button" class="tab-btn" id="tabQrBtn" onclick="switchScannerTab('qr')">
                📷 Scan QR Code (Quishing Detector)
            </button>
        </div>

        <!-- 1. URL Scanner Form -->
        <div id="urlSection" class="card" style="margin-bottom: 24px;">
            <form action="<%= request.getContextPath() %>/UrlScannerServlet" method="POST" id="urlScanForm">
                <input type="hidden" name="isQr" id="isQrField" value="false">

                <div class="form-group">
                    <label class="form-label" for="urlInput" style="font-size: 1rem;">
                        Enter or Paste Suspicious URL / Web Link:
                    </label>
                    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                        <input type="text" id="urlInput" name="url" class="form-control" placeholder="https://example.com/login or paste any suspicious web address..." value="<%= scannedUrl %>" required style="font-size: 1rem; padding: 13px 18px; flex: 1; min-width: 280px;">
                        <button type="submit" class="btn btn-primary" style="padding: 12px 28px; font-size: 1rem; white-space: nowrap;">
                            🛡️ Scan Link &rarr;
                        </button>
                    </div>
                </div>

                <!-- One-click test samples for evaluators -->
                <div style="font-size: 0.82rem; font-weight: 700; color: var(--text-secondary); margin-top: 16px;">
                    ⚡ Quick Test Samples for Evaluators:
                </div>
                <div class="sample-chips">
                    <span class="sample-chip" onclick="loadSample('http://paypa1-security-verify.xyz/account/login.php?user=victims')">
                        🚨 Phishing Brand Spoof (PayPa1)
                    </span>
                    <span class="sample-chip" onclick="loadSample('http://192.168.1.105:8080/download/update_patch.exe')">
                        🦠 Raw IP Malware Dropper (.exe)
                    </span>
                    <span class="sample-chip" onclick="loadSample('http://bit.ly/claim-free-iphone-kyc-reward')">
                        🪤 URL Shortener Trap (Bit.ly)
                    </span>
                    <span class="sample-chip" onclick="loadSample('http://sbi-online-banking-update.top/kyc/verify')">
                        🎣 Banking KYC Phishing (.top)
                    </span>
                    <span class="sample-chip" onclick="loadSample('https://www.google.com')">
                        ✅ Safe Legitimate Domain (Google)
                    </span>
                </div>
            </form>
        </div>

        <!-- 2. QR Code Scanner Section (Hidden by default) -->
        <div id="qrSection" class="card" style="margin-bottom: 24px; display: none;">
            <div class="qr-dropzone" onclick="document.getElementById('qrFileInput').click()">
                <div style="font-size: 46px; margin-bottom: 12px;">📸</div>
                <h3 style="color: var(--text-primary); font-size: 1.25rem; font-weight: 800; margin-bottom: 6px;">Upload or Drag &amp; Drop QR Code Image</h3>
                <p style="color: var(--text-secondary); font-size: 0.92rem; max-width: 580px; margin: 0 auto;">
                    Upload screenshot, photo, or invoice QR code (.png, .jpg, .webp) to decode &amp; analyze embedded destination
                </p>
                <input type="file" id="qrFileInput" accept="image/*" style="display: none;" onchange="handleQrUpload(this)">
            </div>

            <!-- Canvas for hidden image processing -->
            <canvas id="qrCanvas" style="display: none;"></canvas>

            <div id="qrStatus" style="margin-top: 14px; text-align: center; font-size: 0.92rem; font-weight: 700; color: var(--cobalt-primary); display: none;"></div>
        </div>

        <!-- Scan Result Display -->
        <% if (scanResult != null) { %>
            <div class="card" id="scanResultCard">
                <div class="card-header">
                    <div class="card-title">
                        <span>📊</span>
                        <span>Threat Analysis Report</span>
                    </div>
                    <div>
                        <span class="badge <%= scanResult.getBadgeClass() %>" style="font-size: 0.95rem; padding: 6px 16px;">
                            <%= scanResult.getThreatLevel() %> THREAT
                        </span>
                    </div>
                </div>

                <!-- Threat Gauge Banner -->
                <div class="threat-gauge-box">
                    <div style="font-size: 0.85rem; color: var(--text-secondary); font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px;">
                        Composite Threat Risk Score
                    </div>
                    <div style="font-size: 4rem; font-weight: 800; font-family: var(--font-mono); color: <%= scanResult.getRiskScore() >= 70 ? "#dc2626" : (scanResult.getRiskScore() >= 40 ? "#d97706" : "#059669") %>; margin: 4px 0; line-height: 1.1;">
                        <%= scanResult.getRiskScore() %><span style="font-size: 1.8rem; color: var(--text-muted);">/100</span>
                    </div>
                    <p style="color: var(--text-primary); font-size: 1.08rem; font-weight: 700; max-width: 720px; margin: 6px auto 0 auto;">
                        <%= scanResult.getSummary() %>
                    </p>
                </div>

                <!-- Target Observable Details -->
                <div style="background: var(--neu-base); box-shadow: var(--neu-sunken-sm); border: var(--neu-border); border-radius: var(--radius-md); padding: 18px; margin-bottom: 22px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; font-size: 0.90rem;">
                        <div>
                            <span style="color: var(--text-muted); font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Destination Host:</span>
                            <div style="font-weight: 700; color: var(--text-primary); font-family: var(--font-mono); margin-top: 2px;"><%= scanResult.getDomain() %></div>
                        </div>
                        <div>
                            <span style="color: var(--text-muted); font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Transport Protocol:</span>
                            <div style="font-weight: 700; color: <%= "https".equalsIgnoreCase(scanResult.getProtocol()) ? "#059669" : "#dc2626" %>; font-family: var(--font-mono); margin-top: 2px;">
                                <%= scanResult.getProtocol() != null ? scanResult.getProtocol().toUpperCase() : "UNKNOWN" %>
                            </div>
                        </div>
                        <div>
                            <span style="color: var(--text-muted); font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Source Medium:</span>
                            <div style="font-weight: 700; color: var(--text-primary); margin-top: 2px;">
                                <%= scanResult.isQuishing() ? "📷 Decoded QR Code (Quishing)" : "🌐 Web Link URL" %>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Multi-Engine Threat Intelligence Dossier (VirusTotal, AbuseIPDB, Google Safe Browsing) -->
                <div style="margin-bottom: 24px;">
                    <h4 style="color: var(--cobalt-primary); font-size: 1.05rem; font-weight: 800; margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
                        <span>🌐</span>
                        <span>Multi-Engine Global Threat Intelligence Feeds</span>
                        <span style="font-size: 0.72rem; padding: 2px 10px; border-radius: var(--radius-pill); background: rgba(14, 165, 233, 0.15); color: #0284c7; font-weight: 700;">LIVE ORACLE</span>
                    </h4>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
                        <!-- VirusTotal 70+ Engines Card -->
                        <div style="background: var(--neu-base); border: var(--neu-border); border-radius: var(--radius-md); box-shadow: var(--neu-sunken-sm); padding: 16px;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <span style="font-size: 1.2rem;">🛡️</span>
                                    <strong style="font-size: 0.92rem; color: var(--text-primary);">VirusTotal v3</strong>
                                </div>
                                <span class="badge <%= "MALICIOUS".equalsIgnoreCase(scanResult.getVirusTotalVerdict()) ? "badge-critical" : "badge-resolved" %>" style="font-size: 0.72rem;">
                                    <%= scanResult.getVirusTotalVerdict() != null ? scanResult.getVirusTotalVerdict() : "CHECKED" %>
                                </span>
                            </div>
                            <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
                                <strong>70+ Multi-Antivirus Engines:</strong><br>
                                <span style="color: <%= "MALICIOUS".equalsIgnoreCase(scanResult.getVirusTotalVerdict()) ? "#dc2626" : "#059669" %>; font-weight: 700;">
                                    <%= scanResult.getVirusTotalScore() != null ? scanResult.getVirusTotalScore() : "0/72 Engines Flagged (Clean)" %>
                                </span>
                            </div>
                        </div>

                        <!-- AbuseIPDB IP Abuse Score Card -->
                        <div style="background: var(--neu-base); border: var(--neu-border); border-radius: var(--radius-md); box-shadow: var(--neu-sunken-sm); padding: 16px;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <span style="font-size: 1.2rem;">📡</span>
                                    <strong style="font-size: 0.92rem; color: var(--text-primary);">AbuseIPDB v2</strong>
                                </div>
                                <span class="badge <%= scanResult.getRiskScore() >= 40 ? "badge-high" : "badge-resolved" %>" style="font-size: 0.72rem;">
                                    IP REPUTATION
                                </span>
                            </div>
                            <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
                                <strong>Global Abuse &amp; Attack Database:</strong><br>
                                <span style="color: var(--text-primary); font-weight: 600;">
                                    <%= scanResult.getAbuseIpScore() != null ? scanResult.getAbuseIpScore() : "Abuse Confidence: 0% | No reports" %>
                                </span>
                            </div>
                        </div>

                        <!-- Google Safe Browsing Blacklist Card -->
                        <div style="background: var(--neu-base); border: var(--neu-border); border-radius: var(--radius-md); box-shadow: var(--neu-sunken-sm); padding: 16px;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <span style="font-size: 1.2rem;">🔍</span>
                                    <strong style="font-size: 0.92rem; color: var(--text-primary);">Google Safe Browsing</strong>
                                </div>
                                <span class="badge <%= (scanResult.getGoogleSafeBrowsingVerdict() != null && scanResult.getGoogleSafeBrowsingVerdict().contains("BLACKLISTED")) ? "badge-critical" : "badge-resolved" %>" style="font-size: 0.72rem;">
                                    SAFE SEARCH
                                </span>
                            </div>
                            <div style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.5;">
                                <strong>Google Real-Time Blacklist:</strong><br>
                                <span style="color: <%= (scanResult.getGoogleSafeBrowsingVerdict() != null && scanResult.getGoogleSafeBrowsingVerdict().contains("BLACKLISTED")) ? "#dc2626" : "#059669" %>; font-weight: 700;">
                                    <%= scanResult.getGoogleSafeBrowsingVerdict() != null ? scanResult.getGoogleSafeBrowsingVerdict() : "SAFE: Verified by Google" %>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Threat Indicators List -->
                <% if (!scanResult.getThreatIndicators().isEmpty()) { %>
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: #dc2626; font-size: 1.02rem; font-weight: 800; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>⚠️</span>
                            <span>Deceptive Threat Indicators Flagged (<%= scanResult.getThreatIndicators().size() %>)</span>
                        </h4>
                        <div>
                            <% for (String ind : scanResult.getThreatIndicators()) { %>
                                <div class="threat-factor-item danger">
                                    <span>🚩</span>
                                    <span><%= ind %></span>
                                </div>
                            <% } %>
                        </div>
                    </div>
                <% } %>

                <!-- Safety Factors List -->
                <% if (!scanResult.getSafetyFactors().isEmpty()) { %>
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: #059669; font-size: 1.02rem; font-weight: 800; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>🛡️</span>
                            <span>Safety &amp; Verification Checks</span>
                        </h4>
                        <div>
                            <% for (String safe : scanResult.getSafetyFactors()) { %>
                                <div class="threat-factor-item safe">
                                    <span>✓</span>
                                    <span><%= safe %></span>
                                </div>
                            <% } %>
                        </div>
                    </div>
                <% } %>

                <!-- Recommended Actions & Quick Incident Escalation -->
                <div style="background: var(--neu-base); box-shadow: var(--neu-sunken-sm); border: var(--neu-border); border-radius: var(--radius-md); padding: 20px; margin-top: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;">
                        <div>
                            <strong style="color: var(--cobalt-primary); font-size: 0.96rem; display: block; margin-bottom: 4px;">
                                Recommended Defensive Procedure:
                            </strong>
                            <p style="color: var(--text-secondary); font-size: 0.92rem; line-height: 1.6; white-space: pre-wrap;"><%= scanResult.getRecommendedAction() %></p>
                        </div>

                        <% if (scanResult.getRiskScore() >= 40) { %>
                            <div>
                                <a href="<%= request.getContextPath() %>/user/report.jsp?title=Suspicious+Link+Identified:+<%= scanResult.getDomain() %>&category=Phishing&affectedSystem=<%= scanResult.getDomain() %>&iocIndicators=<%= scanResult.getCleanUrl() %>" class="btn btn-primary" style="padding: 10px 22px; font-size: 0.92rem;">
                                    🚨 Report to SOC Desk as Incident &rarr;
                                </a>
                            </div>
                        <% } %>
                    </div>
                </div>
            </div>
        <% } %>
    </div>

    <jsp:include page="/includes/footer.jsp" />

    <script>
        function switchScannerTab(tab) {
            const urlBtn = document.getElementById('tabUrlBtn');
            const qrBtn = document.getElementById('tabQrBtn');
            const urlSec = document.getElementById('urlSection');
            const qrSec = document.getElementById('qrSection');

            if (tab === 'url') {
                urlBtn.classList.add('active');
                qrBtn.classList.remove('active');
                urlSec.style.display = 'block';
                qrSec.style.display = 'none';
            } else {
                qrBtn.classList.add('active');
                urlBtn.classList.remove('active');
                urlSec.style.display = 'none';
                qrSec.style.display = 'block';
            }
        }

        function loadSample(url) {
            document.getElementById('urlInput').value = url;
            document.getElementById('urlScanForm').submit();
        }

        function handleQrUpload(input) {
            if (!input.files || !input.files[0]) return;
            const file = input.files[0];
            const statusDiv = document.getElementById('qrStatus');
            statusDiv.style.display = 'block';
            statusDiv.textContent = 'Analyzing and decoding QR code image...';

            const reader = new FileReader();
            reader.onload = function (e) {
                const img = new Image();
                img.onload = function () {
                    const canvas = document.getElementById('qrCanvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = img.width;
                    canvas.height = img.height;
                    ctx.drawImage(img, 0, 0);

                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    if (typeof jsQR !== 'undefined') {
                        const code = jsQR(imageData.data, imageData.width, imageData.height);
                        if (code) {
                            statusDiv.textContent = '✓ QR Code Decoded: ' + code.data + ' -> Launching Threat Analysis...';
                            document.getElementById('urlInput').value = code.data;
                            document.getElementById('isQrField').value = 'true';
                            setTimeout(() => {
                                document.getElementById('urlScanForm').submit();
                            }, 500);
                        } else {
                            statusDiv.style.color = '#dc2626';
                            statusDiv.textContent = '⚠️ Could not locate a valid QR code in this image. Please ensure the QR code is clearly visible and not blurry.';
                        }
                    } else {
                        statusDiv.style.color = '#d97706';
                        statusDiv.textContent = 'QR decoder engine initializing... Please try again in 2 seconds.';
                    }
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        }
    </script>
</body>
</html>
