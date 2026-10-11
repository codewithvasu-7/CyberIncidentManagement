<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.security.ClientInfoUtil" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Access Gateway - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
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
                <a href="<%= request.getContextPath() %>/index.jsp" class="btn btn-secondary" style="padding: 6px 14px;">Home</a>
                <a href="<%= request.getContextPath() %>/register.jsp" class="btn btn-primary" style="padding: 6px 14px;">Register</a>
            </div>
        </div>
    </nav>

    <div class="auth-wrapper">
        <div class="auth-box">
            <div class="auth-header">
                <div class="auth-icon">🔐</div>
                <h2 class="auth-title">SOC Access Gateway</h2>
                <p style="color: var(--text-secondary); font-size: 0.88rem; margin-top: 4px;">Sign in to authenticate session</p>
            </div>

            <% 
                String error = (String) request.getAttribute("error");
                if (error == null) error = request.getParameter("error");
                String msg = request.getParameter("msg");
                String success = request.getParameter("success");
            %>

            <% if (error != null) { %>
                <div class="alert alert-danger">
                    <span>⚠️</span>
                    <span><%= ClientInfoUtil.escapeHtml(error) %></span>
                </div>
            <% } %>

            <% if (msg != null) { %>
                <div class="alert alert-info">
                    <span>ℹ️</span>
                    <span><%= ClientInfoUtil.escapeHtml(msg) %></span>
                </div>
            <% } %>

            <% if (success != null) { %>
                <div class="alert alert-success">
                    <span>✓</span>
                    <span><%= ClientInfoUtil.escapeHtml(success) %></span>
                </div>
            <% } %>

            <% 
                String prefillUser = request.getParameter("user");
                if (prefillUser == null) prefillUser = "";
            %>
            <form action="<%= request.getContextPath() %>/LoginServlet" method="POST" onsubmit="var f=document.getElementById('client_device_fingerprint'); if(f) f.value=detectClientDevice();">
                <input type="hidden" id="client_device_fingerprint" name="client_device_fingerprint" value="">
                <div class="form-group">
                    <label class="form-label" for="username">Username or Email</label>
                    <input type="text" id="username" name="username" class="form-control" value="<%= ClientInfoUtil.escapeHtml(prefillUser) %>" placeholder="Enter username or email" required autocomplete="username">
                </div>

                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <div style="position: relative;">
                        <input type="password" id="password" name="password" class="form-control" placeholder="Enter password" required autocomplete="current-password" style="padding-right: 42px;">
                        <button type="button" onclick="togglePassVisibility('password', this)" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 16px;" title="Show/Hide Password">
                            👁️
                        </button>
                    </div>
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; margin-top: 10px; font-weight: 700;">
                    Authenticate Session &rarr;
                </button>
            </form>

            <!-- Evaluator Quick Login Helper -->
            <div class="demo-roles">
                <div style="font-size: 0.76rem; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; letter-spacing: 0.8px;">
                    ⚡ EVALUATOR QUICK LOGIN
                </div>
                <div class="demo-pills">
                    <button type="button" class="demo-pill" onclick="quickFill('admin', 'Admin@123')">
                        👑 Admin
                    </button>
                    <button type="button" class="demo-pill" onclick="quickFill('analyst_raj', 'Analyst@123')">
                        🔍 Analyst
                    </button>
                    <button type="button" class="demo-pill" onclick="quickFill('john_doe', 'User@123')">
                        👤 User
                    </button>
                </div>
            </div>

            <div style="text-align: center; margin-top: 24px; font-size: 0.88rem; color: var(--text-secondary);">
                Don't have an enterprise account? 
                <a href="<%= request.getContextPath() %>/register.jsp" style="color: var(--cyan-accent); font-weight: 600;">Register here</a>
            </div>
        </div>
    </div>

    <script>
        function togglePassVisibility(inputId, btn) {
            var field = document.getElementById(inputId);
            if (field.type === 'password') {
                field.type = 'text';
                btn.textContent = '🔒';
            } else {
                field.type = 'password';
                btn.textContent = '👁️';
            }
        }

        function quickFill(user, pass) {
            document.getElementById('username').value = user;
            document.getElementById('password').value = pass;
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
