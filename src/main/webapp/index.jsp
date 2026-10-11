<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User" %>
<%
    User currentUser = (User) session.getAttribute("user");
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Incident Reporting &amp; Management System (CIRMS)</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .hero {
            padding: 70px 0 50px 0;
            text-align: center;
        }
        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 22px;
            background: var(--neu-base);
            border-radius: var(--radius-pill);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            color: var(--cobalt-primary);
            font-size: 0.85rem;
            font-weight: 700;
            margin-bottom: 24px;
        }
        .hero h1 {
            font-size: 3.2rem;
            font-weight: 800;
            letter-spacing: -1.5px;
            line-height: 1.18;
            margin-bottom: 20px;
            color: var(--text-primary);
        }
        .hero p {
            font-size: 1.15rem;
            color: var(--text-secondary);
            max-width: 740px;
            margin: 0 auto 36px auto;
            line-height: 1.6;
        }
        .hero-cta {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            flex-wrap: wrap;
        }
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-top: 50px;
        }
        .feature-card {
            background: var(--neu-base);
            border-radius: var(--radius-lg);
            padding: 30px;
            box-shadow: var(--neu-flat);
            border: var(--neu-border);
            transition: all 0.25s ease;
        }
        .feature-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--neu-raised);
        }
        .feature-icon {
            width: 52px;
            height: 52px;
            border-radius: 16px;
            background: var(--neu-base);
            box-shadow: var(--neu-sunken);
            border: var(--neu-border-subtle);
            color: var(--cobalt-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 18px;
        }
        .workflow-box {
            background: var(--neu-base);
            border-radius: var(--radius-xl);
            padding: 36px 30px;
            margin-top: 60px;
            text-align: center;
            box-shadow: var(--neu-flat);
            border: var(--neu-border);
        }
        .workflow-steps {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-around;
            gap: 20px;
            margin-top: 28px;
        }
        .step-item {
            flex: 1;
            min-width: 200px;
            padding: 22px;
            background: var(--neu-base);
            border-radius: var(--radius-md);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
        }
        .step-num {
            color: var(--cobalt-primary);
            font-weight: 800;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            letter-spacing: 1px;
            margin-bottom: 6px;
        }
    </style>
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
                <li><a href="<%= request.getContextPath() %>/index.jsp" class="active">Home</a></li>
                <li><a href="<%= request.getContextPath() %>/scanner.jsp">🔍 Threat Scanner</a></li>
                <% if (currentUser != null) { %>
                    <% if (currentUser.isAdmin()) { %>
                        <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Admin SOC</a></li>
                    <% } else if (currentUser.isAnalyst()) { %>
                        <li><a href="<%= request.getContextPath() %>/analyst/dashboard.jsp">Analyst Desk</a></li>
                    <% } else { %>
                        <li><a href="<%= request.getContextPath() %>/user/dashboard.jsp">User Desk</a></li>
                    <% } %>
                    <li><a href="<%= request.getContextPath() %>/user/report.jsp">+ Report Incident</a></li>
                <% } %>
            </ul>
            <div class="nav-user">
                <% if (currentUser == null) { %>
                    <a href="<%= request.getContextPath() %>/login.jsp" class="btn btn-secondary">Sign In</a>
                    <a href="<%= request.getContextPath() %>/register.jsp" class="btn btn-primary">Register</a>
                <% } else { %>
                    <span style="font-size: 0.9rem; color: var(--text-primary); font-weight: 700;">
                        <%= currentUser.getFullName() %>
                    </span>
                    <span class="role-badge <%= currentUser.getRole().toLowerCase() %>">
                        <%= currentUser.getRole() %>
                    </span>
                    <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger btn-sm">Sign Out</a>
                <% } %>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <div class="container">
        <div class="hero">
            <div class="hero-badge">
                <span>⚡ Next-Generation SOC Incident Response Engine</span>
            </div>
            <h1>Cybersecurity Incident Reporting<br>&amp; Management System</h1>
            <p>
                An enterprise-grade CSIRT &amp; SOC operations platform. Report security threats, execute multi-factor risk assessments, scan malicious phishing links and QR codes, and maintain immutable audit chains.
            </p>
            <div class="hero-cta">
                <a href="<%= request.getContextPath() %>/scanner.jsp" class="btn btn-primary" style="padding: 12px 28px; font-size: 1rem;">
                    🔍 Threat Scanner (Link &amp; QR)
                </a>
                <% if (currentUser == null) { %>
                    <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-secondary" style="padding: 12px 24px;">
                        🚨 Report Incident / Data Fetch Query &rarr;
                    </a>
                <% } else { %>
                    <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-secondary" style="padding: 12px 24px;">
                        🚨 Report Incident &amp; Query Resolution &rarr;
                    </a>
                <% } %>
            </div>
        </div>

        <!-- System Architecture Highlights -->
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon">🚨</div>
                <h3 style="margin-bottom: 10px; color: var(--text-primary); font-size: 1.15rem; font-weight: 800;">Automated Threat Triage</h3>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Instant classification of Phishing, Ransomware, Malware, DDoS, and Data Exfiltration vectors with automated severity ranking.
                </p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔍</div>
                <h3 style="margin-bottom: 10px; color: var(--text-primary); font-size: 1.15rem; font-weight: 800;">Phishing &amp; QR Detection</h3>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Advanced heuristics detect typosquatting lures, homograph attacks, suspicious TLDs, and malicious QR code redirects.
                </p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📋</div>
                <h3 style="margin-bottom: 10px; color: var(--text-primary); font-size: 1.15rem; font-weight: 800;">NIST SP 800-61 Playbooks</h3>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Automated generation of containment strategies, forensic checklists, and chain-of-custody tracking for SOC responders.
                </p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3 style="margin-bottom: 10px; color: var(--text-primary); font-size: 1.15rem; font-weight: 800;">Role-Based Access (RBAC)</h3>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Strict tripartite security boundaries isolating regular enterprise Users, SOC Security Analysts, and Chief Security Officers.
                </p>
            </div>
        </div>

        <!-- 4-Stage SOC Workflow -->
        <div class="workflow-box">
            <h3 style="color: var(--text-primary); font-size: 1.35rem; font-weight: 800;">Standard Incident Response Lifecycle</h3>
            <div class="workflow-steps">
                <div class="step-item">
                    <div class="step-num">PHASE 01</div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem;">Detection &amp; Report</strong>
                    <p style="color: var(--text-secondary); font-size: 0.84rem; margin-top: 4px;">User or SIEM alert raises anomalous activity with telemetry.</p>
                </div>
                <div class="step-item">
                    <div class="step-num">PHASE 02</div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem;">Triage &amp; Risk Score</strong>
                    <p style="color: var(--text-secondary); font-size: 0.84rem; margin-top: 4px;">Security engine calculates 0-100 risk score and priority queue.</p>
                </div>
                <div class="step-item">
                    <div class="step-num">PHASE 03</div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem;">Containment &amp; Eradication</strong>
                    <p style="color: var(--text-secondary); font-size: 0.84rem; margin-top: 4px;">Analyst isolates affected assets, extracts IOCs, neutralizes payload.</p>
                </div>
                <div class="step-item">
                    <div class="step-num">PHASE 04</div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem;">Post-Incident &amp; Audit</strong>
                    <p style="color: var(--text-secondary); font-size: 0.84rem; margin-top: 4px;">Root cause documented, metrics published to executive reports.</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer>
        <div class="container">
            <p>Cybersecurity Incident Reporting &amp; Management System (CIRMS) &bull; Major Project MVC Implementation</p>
        </div>
    </footer>

</body>
</html>
