<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    String footerCtx = request.getContextPath();
%>
<footer class="cirms-footer">
    <div class="footer-container">
        <div class="footer-grid">
            <!-- Brand & Mission Column -->
            <div class="footer-col brand-col">
                <div class="footer-brand">
                    <div class="footer-brand-icon">🛡️</div>
                    <div class="footer-brand-title">
                        <span class="brand-name">CIRMS</span>
                        <span class="brand-tag">SOC PLATFORM</span>
                    </div>
                </div>
                <p class="footer-desc">
                    Enterprise Cybersecurity Incident Reporting &amp; Management System. Next-gen threat intelligence, triage automation, and compliant security audit trail.
                </p>
                <div class="footer-status-pill">
                    <span class="status-indicator-dot"></span>
                    <span>SOC Operations 24/7/365 &bull; Active</span>
                </div>
            </div>

            <!-- Emergency Contact & Incident Support Column -->
            <div class="footer-col">
                <h4 class="footer-heading">🚨 Security Desk &amp; Inquiries</h4>
                <p class="footer-text-sm">
                    Report zero-day findings, security anomalies, or reach platform administrators:
                </p>
                <div class="footer-email-box">
                    <a href="mailto:cyberincidentmanagement@gmail.com" class="footer-email-link" title="Send email to CIRMS Security Desk">
                        <span class="email-icon">📧</span>
                        <span class="email-address">cyberincidentmanagement@gmail.com</span>
                    </a>
                    <button type="button" class="footer-copy-btn" onclick="copyFooterEmail(this)" title="Copy email address">
                        <span class="copy-icon">📋</span>
                        <span class="copy-text">Copy</span>
                    </button>
                </div>
                <div class="footer-sla-info">
                    <span>⚡ Critical Incident Triage SLA: <strong>&lt; 15 Mins</strong></span>
                    <span>🔒 End-to-End Encrypted Communication Channel</span>
                </div>
            </div>

            <!-- Rapid Navigation Column -->
            <div class="footer-col">
                <h4 class="footer-heading">⚡ Quick Navigation</h4>
                <ul class="footer-nav-list">
                    <li><a href="<%= footerCtx %>/index.jsp">🏠 Platform Overview</a></li>
                    <li><a href="<%= footerCtx %>/scanner.jsp">🔍 Cyber Threat &amp; URL Scanner</a></li>
                    <li><a href="<%= footerCtx %>/LoginServlet">🔐 Secure SOC Sign In</a></li>
                    <li><a href="<%= footerCtx %>/user/report.jsp">🚨 Report New Incident</a></li>
                    <li><a href="<%= footerCtx %>/admin/reports.jsp">📜 Security Audit &amp; Telemetry</a></li>
                </ul>
            </div>

            <!-- Framework Compliance Column -->
            <div class="footer-col">
                <h4 class="footer-heading">🛡️ Governance &amp; Standards</h4>
                <div class="footer-badge-list">
                    <div class="footer-compliance-badge">
                        <span class="badge-icon">🇮🇳</span>
                        <span>CERT-In Cyber Guidelines Aligned</span>
                    </div>
                    <div class="footer-compliance-badge">
                        <span class="badge-icon">🏛️</span>
                        <span>ISO/IEC 27001 ISMS Standard</span>
                    </div>
                    <div class="footer-compliance-badge">
                        <span class="badge-icon">📊</span>
                        <span>NIST SP 800-61 Incident Framework</span>
                    </div>
                    <div class="footer-compliance-badge">
                        <span class="badge-icon">🔐</span>
                        <span>SHA-256 Salted Hash Integrity</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer Bottom Bar -->
        <div class="footer-bottom">
            <div class="footer-copy">
                &copy; 2026 <strong>CIRMS</strong> &bull; Cybersecurity Incident Reporting &amp; Management System.
            </div>
            <div class="footer-meta">
                <span class="footer-meta-pill">🇮🇳 IST (UTC+5:30)</span>
                <span class="footer-meta-sep">&bull;</span>
                <a href="mailto:cyberincidentmanagement@gmail.com" class="footer-meta-email">cyberincidentmanagement@gmail.com</a>
            </div>
        </div>
    </div>
</footer>

<script>
function copyFooterEmail(btn) {
    const email = "cyberincidentmanagement@gmail.com";
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(email).then(function() {
            showCopiedState(btn);
        }).catch(function() {
            fallbackCopy(email, btn);
        });
    } else {
        fallbackCopy(email, btn);
    }
}
function fallbackCopy(text, btn) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand('copy');
        showCopiedState(btn);
    } catch (err) {}
    document.body.removeChild(textArea);
}
function showCopiedState(btn) {
    const copyText = btn.querySelector('.copy-text');
    const copyIcon = btn.querySelector('.copy-icon');
    const origText = copyText ? copyText.innerText : 'Copy';
    const origIcon = copyIcon ? copyIcon.innerText : '📋';
    if (copyText) copyText.innerText = 'Copied!';
    if (copyIcon) copyIcon.innerText = '✅';
    btn.classList.add('copied');
    setTimeout(function() {
        if (copyText) copyText.innerText = origText;
        if (copyIcon) copyIcon.innerText = origIcon;
        btn.classList.remove('copied');
    }, 2000);
}
</script>
