<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.security.ClientInfoUtil" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Registration - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .auth-box {
            max-width: 560px;
        }
        .form-row {
            display: flex;
            gap: 16px;
        }
        .form-row .form-group {
            flex: 1;
        }
        .password-meter-wrap {
            height: 7px;
            background: var(--neu-base);
            box-shadow: var(--neu-sunken-sm);
            border-radius: var(--radius-pill);
            margin-top: 8px;
            overflow: hidden;
            border: var(--neu-border-subtle);
        }
        .password-meter-bar {
            height: 100%;
            width: 0%;
            transition: all 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">🛡️</div>
                <span>CIRMS</span>
            </a>
            <div class="nav-user">
                <a href="<%= request.getContextPath() %>/login.jsp" class="btn btn-secondary">Sign In</a>
            </div>
        </div>
    </nav>

    <div class="auth-wrapper">
        <div class="auth-box">
            <div class="auth-header">
                <div class="auth-icon">📝</div>
                <h2 class="auth-title">Employee Registration</h2>
                <p style="color: var(--text-secondary); font-size: 0.88rem; margin-top: 4px;">Create your enterprise incident reporting identity</p>
            </div>

            <% 
                String error = (String) request.getAttribute("error");
                if (error == null) error = request.getParameter("error");
            %>

            <% if (error != null) { %>
                <div class="alert alert-danger">
                    <span>⚠️</span>
                    <span><%= ClientInfoUtil.escapeHtml(error) %></span>
                </div>
            <% } %>

            <form action="<%= request.getContextPath() %>/RegisterServlet" method="POST" onsubmit="var f=document.getElementById('client_device_fingerprint'); if(f) f.value=detectClientDevice();">
                <input type="hidden" id="client_device_fingerprint" name="client_device_fingerprint" value="">
                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label" for="username">Username</label>
                        <input type="text" id="username" name="username" class="form-control" placeholder="e.g. john_doe" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="fullName">Full Name</label>
                        <input type="text" id="fullName" name="fullName" class="form-control" placeholder="e.g. John Doe" required autocomplete="name">
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="email">Work Email</label>
                    <input type="email" id="email" name="email" class="form-control" placeholder="name@company.com" required autocomplete="email">
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label class="form-label" for="department">Department</label>
                        <select id="department" name="department" class="form-control" required>
                            <option value="">Select Department</option>
                            <option value="IT Operations">IT Operations</option>
                            <option value="Software Engineering">Software Engineering</option>
                            <option value="Finance & Accounting">Finance &amp; Accounting</option>
                            <option value="Human Resources">Human Resources</option>
                            <option value="Sales & Marketing">Sales &amp; Marketing</option>
                            <option value="Legal & Compliance">Legal &amp; Compliance</option>
                            <option value="Executive Office">Executive Office</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="role">Requested Role</label>
                        <select id="role" name="role" class="form-control" required>
                            <option value="USER" selected>Employee (User)</option>
                            <option value="ANALYST">SOC Security Analyst</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" placeholder="Minimum 8 characters" required onkeyup="checkPasswordStrength(this.value)">
                    <div class="password-meter-wrap">
                        <div id="passwordStrengthBar" class="password-meter-bar"></div>
                    </div>
                    <div id="passwordFeedback" style="font-size: 0.76rem; color: var(--text-muted); margin-top: 6px;"></div>
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; margin-top: 10px; font-weight: 700;">
                    Complete Registration &rarr;
                </button>
            </form>

            <div style="text-align: center; margin-top: 24px; font-size: 0.88rem; color: var(--text-secondary);">
                Already registered? 
                <a href="<%= request.getContextPath() %>/login.jsp" style="color: var(--cyan-accent); font-weight: 600;">Sign In here</a>
            </div>
        </div>
    </div>

    <!-- Reusable Enterprise Footer -->
    <jsp:include page="/includes/footer.jsp" />

    <script>
        function checkPasswordStrength(val) {
            var bar = document.getElementById('passwordStrengthBar');
            var feedback = document.getElementById('passwordFeedback');
            var score = 0;
            if (val.length >= 8) score += 25;
            if (/[A-Z]/.test(val)) score += 25;
            if (/[0-9]/.test(val)) score += 25;
            if (/[^A-Za-z0-9]/.test(val)) score += 25;

            bar.style.width = score + '%';
            if (score <= 25) {
                bar.style.background = '#f43f5e';
                feedback.textContent = 'Weak password';
                feedback.style.color = '#fda4af';
            } else if (score <= 50) {
                bar.style.background = '#f59e0b';
                feedback.textContent = 'Medium password';
                feedback.style.color = '#fde047';
            } else if (score <= 75) {
                bar.style.background = '#0284c7';
                feedback.textContent = 'Good password';
                feedback.style.color = '#7dd3fc';
            } else {
                bar.style.background = '#10b981';
                feedback.textContent = 'Strong password';
                feedback.style.color = '#6ee7b7';
            }
        }

        function detectClientDevice() {
            try {
                var isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
                var ua = navigator.userAgent || "";
                var isMobileWidth = window.innerWidth <= 850;
                var uad = navigator.userAgentData;
                
                var isMobile = false;
                if (uad && typeof uad.mobile === 'boolean') {
                    isMobile = uad.mobile;
                }
                if (/Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|webOS/i.test(ua)) {
                    isMobile = true;
                }
                if (isTouch && isMobileWidth) {
                    isMobile = true;
                }
                
                // Detect OS
                var os = "Desktop";
                var icon = "💻";
                if (/iPhone/i.test(ua)) {
                    os = "Apple iPhone (iOS)";
                    icon = "📱";
                } else if (/iPad/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)) {
                    os = "Apple iPad (iPadOS)";
                    icon = "📱";
                } else if (/Android/i.test(ua) || (uad && uad.platform === 'Android') || (isTouch && /Linux/i.test(navigator.platform))) {
                    os = (isMobileWidth || isMobile) ? "Android Phone" : "Android Tablet";
                    icon = "📱";
                } else if (isMobile) {
                    os = "Mobile Phone";
                    icon = "📱";
                } else if (/Windows/i.test(ua)) {
                    os = "Windows 10/11";
                    icon = "💻";
                } else if (/Macintosh|Mac OS/i.test(ua)) {
                    os = "Apple Mac (macOS)";
                    icon = "💻";
                } else if (/Linux/i.test(ua)) {
                    os = (isTouch || isMobileWidth) ? "Android Phone" : "Linux Desktop";
                    icon = (isTouch || isMobileWidth) ? "📱" : "🐧";
                }

                // Detect Browser
                var browser = "Browser";
                if (/Edg/i.test(ua)) browser = "Edge";
                else if (/SamsungBrowser/i.test(ua)) browser = "Samsung Internet";
                else if (/Chrome/i.test(ua)) browser = "Chrome";
                else if (/Firefox/i.test(ua)) browser = "Firefox";
                else if (/Safari/i.test(ua)) browser = "Safari";
                else if (/Opera|OPR/i.test(ua)) browser = "Opera";

                return icon + " " + os + " • " + browser;
            } catch (e) {
                return "💻 Desktop • Web Browser";
            }
        }

        // Set device fingerprint on load
        (function() {
            var el = document.getElementById('client_device_fingerprint');
            if (el) el.value = detectClientDevice();
        })();
    </script>
</body>
</html>
