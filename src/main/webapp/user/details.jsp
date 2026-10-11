<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.model.IncidentUpdate, com.cyberincident.dao.IncidentDAO, com.cyberincident.security.ClientInfoUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null) {
        response.sendRedirect(request.getContextPath() + "/login.jsp");
        return;
    }

    Incident incident = (Incident) request.getAttribute("incident");
    List<IncidentUpdate> updates = (List<IncidentUpdate>) request.getAttribute("updates");

    if (incident == null) {
        String idStr = request.getParameter("id");
        if (idStr != null) {
            IncidentDAO dao = new IncidentDAO();
            int id = Integer.parseInt(idStr);
            incident = dao.getIncidentById(id);
            updates = dao.getIncidentUpdates(id);
        }
    }

    if (incident == null) {
        response.sendRedirect(request.getContextPath() + "/user/incidents.jsp?error=Incident not found");
        return;
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= incident.getIncidentCode() %> Forensic Dossier - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .details-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }
        @media (max-width: 900px) {
            .details-grid {
                grid-template-columns: 1fr;
            }
        }
        .meta-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 12px;
            padding: 0;
            margin: 0;
        }
        .meta-item {
            display: flex;
            justify-content: space-between;
            font-size: 0.88rem;
            padding-bottom: 8px;
            border-bottom: var(--neu-border-subtle);
        }
        .meta-label {
            color: var(--text-secondary);
        }
        .meta-val {
            color: var(--text-primary);
            font-weight: 700;
        }
        .forensic-card {
            background: var(--neu-surface);
            box-shadow: var(--neu-flat);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }
        .forensic-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--cobalt-primary), var(--cobalt-light), var(--amber-warning));
        }
        .dossier-pill-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 14px 0;
        }
        @media (max-width: 650px) {
            .dossier-pill-grid {
                grid-template-columns: 1fr;
            }
        }
        .dossier-pill {
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-md);
            padding: 12px 14px;
            font-size: 0.86rem;
            color: var(--text-primary);
            display: flex;
            align-items: flex-start;
            gap: 10px;
            line-height: 1.5;
        }
        .remediation-checklist {
            list-style: none;
            padding: 0;
            margin: 14px 0;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .remediation-item {
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-md);
            padding: 12px 16px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            font-size: 0.88rem;
            color: var(--text-primary);
            line-height: 1.5;
            transition: all 0.2s ease;
        }
        .remediation-item:hover {
            box-shadow: var(--neu-raised-sm);
        }
        .remediation-checkbox {
            margin-top: 3px;
            accent-color: var(--cobalt-primary);
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        .remediation-text.checked {
            text-decoration: line-through;
            color: var(--text-muted);
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
                <span class="brand-badge">Forensic Desk</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/user/dashboard.jsp">Dashboard</a></li>
                <li>
                    <a href="<%= request.getContextPath() %>/scanner.jsp">
                        <svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                        Threat Scanner
                    </a>
                </li>
                <li><a href="<%= request.getContextPath() %>/user/report.jsp">+ Report Incident</a></li>
                <li><a href="<%= request.getContextPath() %>/user/incidents.jsp">My Incidents</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge <%= currentUser.getRole().toLowerCase() %>"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <!-- Top Bar Navigation & Actions -->
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 14px;">
            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <a href="<%= request.getContextPath() %>/user/incidents.jsp" class="btn btn-secondary" style="padding: 6px 14px; font-size: 0.85rem;">
                    &larr; Back to Incidents
                </a>
                <span class="incident-code" style="font-size: 1.3rem;"><%= incident.getIncidentCode() %></span>
                <span class="badge <%= incident.getSeverityBadgeClass() %>"><%= incident.getSeverity() %></span>
                <span class="badge <%= incident.getStatusBadgeClass() %>"><%= incident.getStatus() %></span>
            </div>

            <div style="display: flex; align-items: center; gap: 10px;">
                <a href="<%= request.getContextPath() %>/ExportReportServlet?id=<%= incident.getId() %>" target="_blank" class="btn btn-primary" style="padding: 8px 16px; font-size: 0.88rem; display: inline-flex; align-items: center; gap: 8px;">
                    <span>📄</span>
                    <span>Export Printable Forensic PDF</span>
                </a>
                <% if (currentUser.isAnalyst() || currentUser.isAdmin()) { %>
                    <a href="<%= request.getContextPath() %>/IncidentServlet?action=investigate&id=<%= incident.getId() %>" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.88rem;">
                        <span>🔍</span>
                        <span>SOC Investigation Desk &rarr;</span>
                    </a>
                <% } %>
            </div>
        </div>

        <%
            String curStat = incident.getStatus() != null ? incident.getStatus().toUpperCase() : "REPORTED";
            int stage = 1;
            if ("UNDER_REVIEW".equals(curStat)) stage = 2;
            else if ("INVESTIGATING".equals(curStat)) stage = 3;
            else if ("CONTAINED".equals(curStat)) stage = 4;
            else if ("RESOLVED".equals(curStat)) stage = 5;
            else if ("CLOSED".equals(curStat)) stage = 6;
        %>
        <!-- Incident Progression Stepper -->
        <div class="card" style="margin-bottom: 24px; padding: 16px 20px;">
            <div class="stepper-wrapper" style="margin: 10px 0;">
                <div class="stepper-step <%= stage > 1 ? "completed" : (stage == 1 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 1 ? "✓" : "1" %></div>
                    <div class="stepper-title">Reported</div>
                </div>
                <div class="stepper-step <%= stage > 2 ? "completed" : (stage == 2 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 2 ? "✓" : "2" %></div>
                    <div class="stepper-title">Triage</div>
                </div>
                <div class="stepper-step <%= stage > 3 ? "completed" : (stage == 3 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 3 ? "✓" : "3" %></div>
                    <div class="stepper-title">Investigating</div>
                </div>
                <div class="stepper-step <%= stage > 4 ? "completed" : (stage == 4 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 4 ? "✓" : "4" %></div>
                    <div class="stepper-title">Contained</div>
                </div>
                <div class="stepper-step <%= stage > 5 ? "completed" : (stage == 5 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 5 ? "✓" : "5" %></div>
                    <div class="stepper-title">Resolved</div>
                </div>
                <div class="stepper-step <%= stage == 6 ? "active completed" : "" %>">
                    <div class="stepper-dot"><%= stage == 6 ? "✓" : "6" %></div>
                    <div class="stepper-title">Closed</div>
                </div>
            </div>
        </div>

        <!-- SPECIAL FORENSIC RESOLUTION DOSSIER CARD (What Happened to You, Compromised Data, Emergency Plan) -->
        <div class="forensic-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
                <div>
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                        <span style="font-size: 1.4rem;">🔬</span>
                        <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.01em; margin: 0;">
                            Automated Incident Forensic Resolution Dossier
                        </h2>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; margin: 0;">
                        Deep technical root-cause determination, compromised asset assessment, and step-by-step emergency recovery directives.
                    </p>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <span class="badge badge-<%= incident.getSeverity().toLowerCase() %>" style="font-size: 0.85rem; padding: 6px 12px;">
                        Risk Score: <%= incident.getRiskScore() %>/100 (<%= incident.getRiskLevel() %>)
                    </span>
                </div>
            </div>

            <!-- "What Happened To You?" Narrative -->
            <div style="background: var(--neu-surface); box-shadow: var(--neu-sunken-sm); border: var(--neu-border-subtle); border-radius: var(--radius-md); padding: 18px 20px; margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 8px; color: var(--cobalt-primary); font-weight: 700; font-size: 0.96rem; margin-bottom: 10px;">
                    <span>🔍</span>
                    <span>1. Root Cause Breakdown: What Happened to You?</span>
                </div>
                <% if (incident.getRootCause() != null && !incident.getRootCause().trim().isEmpty()) { %>
                    <div style="color: var(--text-primary); font-size: 0.9rem; line-height: 1.7; white-space: pre-wrap;"><%= ClientInfoUtil.escapeHtml(incident.getRootCause()) %></div>
                <% } else { %>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.7;">
                        When you clicked the suspicious link, your web browser established a connection with the remote attacker server. The destination executed client-side scripts to harvest browser telemetry, active session cookies, and public IP address. If credentials or OTP were entered, they were intercepted in real-time.
                    </p>
                <% } %>
            </div>

            <!-- "What Data Was Potentially Compromised?" Grid -->
            <div style="margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 8px; color: var(--amber-warning); font-weight: 700; font-size: 0.96rem; margin-bottom: 8px;">
                    <span>⚠️</span>
                    <span>2. Potentially Compromised Data Assets:</span>
                </div>
                <div class="dossier-pill-grid">
                    <div class="dossier-pill">
                        <span style="font-size: 1.1rem;">🔑</span>
                        <div>
                            <strong style="display: block; color: var(--text-primary);">Submitted Credentials &amp; Passwords</strong>
                            <span style="color: var(--text-secondary); font-size: 0.82rem;">Captured if entered into fake login prompts or spoofed verification pages.</span>
                        </div>
                    </div>
                    <div class="dossier-pill">
                        <span style="font-size: 1.1rem;">🍪</span>
                        <div>
                            <strong style="display: block; color: var(--text-primary);">Active Session Cookies &amp; Auth Tokens</strong>
                            <span style="color: var(--text-secondary); font-size: 0.82rem;">Risk of unauthorized account takeover via stolen session identifiers.</span>
                        </div>
                    </div>
                    <div class="dossier-pill">
                        <span style="font-size: 1.1rem;">🌐</span>
                        <div>
                            <strong style="display: block; color: var(--text-primary);">Public IP &amp; Network Geolocation</strong>
                            <span style="color: var(--text-secondary); font-size: 0.82rem;">Exposed via standard HTTP handshake telemetry upon page load.</span>
                        </div>
                    </div>
                    <div class="dossier-pill">
                        <span style="font-size: 1.1rem;">📱</span>
                        <div>
                            <strong style="display: block; color: var(--text-primary);">Device Fingerprint &amp; Browser Cache</strong>
                            <span style="color: var(--text-secondary); font-size: 0.82rem;">OS version, screen dimensions, user-agent, and prefilled autofill fields.</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- "Step-by-Step Emergency Remediation Plan" with Interactive Checklist -->
            <div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
                    <div style="display: flex; align-items: center; gap: 8px; color: var(--cobalt-primary); font-weight: 700; font-size: 0.96rem;">
                        <span>🛡️</span>
                        <span>3. Step-by-Step Emergency Recovery Directives:</span>
                    </div>
                    <span style="font-size: 0.8rem; color: var(--text-secondary);">Check off items as you complete each step:</span>
                </div>

                <ul class="remediation-checklist" id="remediationList">
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem1" onchange="toggleRem(this)">
                        <label for="rem1" class="remediation-text" style="cursor: pointer;">
                            <strong>[CRITICAL] Reset Account Passwords Immediately:</strong> Change passwords for email, banking, and primary accounts using a separate clean device (do not reset on the affected device until scanned).
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem2" onchange="toggleRem(this)">
                        <label for="rem2" class="remediation-text" style="cursor: pointer;">
                            <strong>[CRITICAL] Terminate All Active Sessions:</strong> Open Google, Microsoft, Apple, and social media security settings and click <em>"Log Out of All Devices / Revoke All Sessions"</em> to invalidate stolen session cookies.
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem3" onchange="toggleRem(this)">
                        <label for="rem3" class="remediation-text" style="cursor: pointer;">
                            <strong>[HIGH] Enable App-Based Two-Factor Authentication (2FA):</strong> Switch to an Authenticator app (Google Authenticator / Microsoft Authenticator) instead of SMS-based verification.
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem4" onchange="toggleRem(this)">
                        <label for="rem4" class="remediation-text" style="cursor: pointer;">
                            <strong>[HIGH] Purge Browser Cache &amp; Storage:</strong> In your browser settings, clear cookies, local storage, site permissions, and cached data for "All Time".
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem5" onchange="toggleRem(this)">
                        <label for="rem5" class="remediation-text" style="cursor: pointer;">
                            <strong>[HIGH] Revoke Unrecognized App Permissions:</strong> Review third-party apps connected to your Google/Microsoft account and remove unknown extensions or permissions.
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem6" onchange="toggleRem(this)">
                        <label for="rem6" class="remediation-text" style="cursor: pointer;">
                            <strong>[MEDIUM] Run Deep Antivirus &amp; Anti-Malware Scan:</strong> Perform a comprehensive scan (Windows Defender / Malwarebytes) to verify no persistent dropper or spyware executable was installed.
                        </label>
                    </li>
                    <li class="remediation-item">
                        <input type="checkbox" class="remediation-checkbox" id="rem7" onchange="toggleRem(this)">
                        <label for="rem7" class="remediation-text" style="cursor: pointer;">
                            <strong>[FINANCIAL] Notify Banking Helplines:</strong> If credit card or payment credentials were stored or entered, notify your bank immediately to freeze transactions.
                        </label>
                    </li>
                </ul>
            </div>

            <!-- Containment Plan & IOCs -->
            <% if (incident.getContainmentPlan() != null && !incident.getContainmentPlan().isEmpty()) { %>
                <div style="margin-top: 18px; background: rgba(59, 130, 246, 0.06); border: var(--neu-border-subtle); border-radius: var(--radius-md); padding: 16px;">
                    <strong style="color: var(--cobalt-primary); font-size: 0.92rem; display: block; margin-bottom: 6px;">
                        🏛️ SOC Network Containment Strategy:
                    </strong>
                    <div style="color: var(--text-primary); font-size: 0.88rem; line-height: 1.6; white-space: pre-wrap;"><%= ClientInfoUtil.escapeHtml(incident.getContainmentPlan()) %></div>
                </div>
            <% } %>
        </div>

        <div class="details-grid">
            <!-- Left: Incident Overview & Timeline -->
            <div style="display: flex; flex-direction: column; gap: 24px;">
                <!-- Main Incident Info -->
                <div class="card">
                    <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); margin-bottom: 12px; letter-spacing: -0.01em;">
                        <%= ClientInfoUtil.escapeHtml(incident.getTitle()) %>
                    </h2>
                    <p style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.7; white-space: pre-wrap; margin-bottom: 20px;">
                        <%= ClientInfoUtil.escapeHtml(incident.getDescription()) %>
                    </p>

                    <% if (incident.getIocIndicators() != null && !incident.getIocIndicators().isEmpty()) { %>
                        <div style="margin-top: 16px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
                                <span style="font-size: 0.85rem; font-weight: 700; color: var(--text-primary);">Indicators of Compromise (IOCs / Reported Links):</span>
                                <div style="display: flex; gap: 8px;">
                                    <button type="button" class="btn btn-secondary copy-btn" data-copy="<%= ClientInfoUtil.escapeHtml(incident.getIocIndicators()) %>" style="padding: 4px 10px; font-size: 0.78rem;">
                                        Copy Link
                                    </button>
                                    <a href="<%= request.getContextPath() %>/scanner.jsp?url=<%= java.net.URLEncoder.encode(incident.getIocIndicators(), "UTF-8") %>" class="btn btn-primary" style="padding: 4px 10px; font-size: 0.78rem;">
                                        Detonate in Scanner &rarr;
                                    </a>
                                </div>
                            </div>
                            <div class="ioc-box"><%= ClientInfoUtil.escapeHtml(incident.getIocIndicators()) %></div>
                        </div>
                    <% } %>
                </div>

                <!-- Incident Activity Timeline -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>⏱️</span>
                            <span>Incident Chronology &amp; Investigation Notes</span>
                        </div>
                    </div>

                    <% if (updates != null && !updates.isEmpty()) { %>
                        <div class="timeline">
                            <% for (IncidentUpdate up : updates) { %>
                                <div class="timeline-item">
                                    <div class="timeline-dot"></div>
                                    <div class="timeline-content">
                                        <div class="timeline-meta">
                                            <strong>
                                                <%= ClientInfoUtil.escapeHtml(up.getAuthorName()) %> 
                                                <span class="role-badge <%= up.getAuthorRole().toLowerCase() %>" style="font-size: 0.7rem; padding: 2px 6px;">
                                                    <%= up.getAuthorRole() %>
                                                </span>
                                            </strong>
                                            <span><%= up.getCreatedAt() != null ? up.getCreatedAt().toString().substring(0, 16) : "" %></span>
                                        </div>
                                        <% if (up.getStatusChange() != null && !up.getStatusChange().isEmpty()) { %>
                                            <div style="margin-bottom: 6px;">
                                                <span class="badge badge-review" style="font-size: 0.72rem;">Status Transition: <%= up.getStatusChange() %></span>
                                            </div>
                                        <% } %>
                                        <p style="color: var(--text-primary); font-size: 0.9rem; line-height: 1.6;"><%= ClientInfoUtil.escapeHtml(up.getNotes()) %></p>
                                        <% if (up.getActionTaken() != null && !up.getActionTaken().isEmpty()) { %>
                                            <div style="font-size: 0.82rem; color: var(--cobalt-primary); font-weight: 600; margin-top: 4px;">
                                                Action Executed: <%= ClientInfoUtil.escapeHtml(up.getActionTaken()) %>
                                            </div>
                                        <% } %>
                                    </div>
                                </div>
                            <% } %>
                        </div>
                    <% } else { %>
                        <p style="color: var(--text-muted); font-size: 0.88rem;">No chronology logs found.</p>
                    <% } %>

                    <!-- Add note/evidence form -->
                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST" style="margin-top: 20px; border-top: var(--neu-border-subtle); padding-top: 16px;">
                        <input type="hidden" name="action" value="addNote">
                        <input type="hidden" name="id" value="<%= incident.getId() %>">

                        <div class="form-group">
                            <label class="form-label">Add Supplemental Evidence / User Notes</label>
                            <textarea name="notes" class="form-control" rows="3" placeholder="Provide additional findings, screenshot descriptions, or symptoms observed..." required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary" style="padding: 8px 16px; font-size: 0.88rem;">
                            Post Update to Timeline
                        </button>
                    </form>
                </div>
            </div>

            <!-- Right Sidebar: Threat & Asset Details -->
            <div style="display: flex; flex-direction: column; gap: 20px;">
                <!-- Risk & Threat Score Card -->
                <div class="card" style="text-align: center;">
                    <div style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-secondary); font-weight: 700; letter-spacing: 0.5px;">
                        Calculated Threat Risk
                    </div>
                    <div style="font-size: 3.5rem; font-weight: 800; font-family: var(--font-mono); margin: 6px 0; color: <%= incident.getRiskScore() >= 85 ? "var(--rose-danger)" : (incident.getRiskScore() >= 65 ? "var(--amber-warning)" : "var(--cobalt-primary)") %>;">
                        <%= incident.getRiskScore() %>
                    </div>
                    <div>
                        <span class="badge <%= incident.getSeverityBadgeClass() %>" style="font-size: 0.9rem; padding: 6px 14px;">
                            <%= incident.getRiskLevel() %> RISK
                        </span>
                    </div>
                </div>

                <!-- Meta Details Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>ℹ️</span>
                            <span>Incident Profile</span>
                        </div>
                    </div>
                    <ul class="meta-list">
                        <li class="meta-item">
                            <span class="meta-label">Category</span>
                            <span class="meta-val"><%= incident.getCategory() %></span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Target Asset</span>
                            <span class="meta-val"><%= incident.getAffectedSystem() %></span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Impact Scope</span>
                            <span class="meta-val"><%= incident.getImpactScope() %></span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Data Sensitivity</span>
                            <span class="meta-val"><%= incident.getDataSensitivity() %></span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Reporter</span>
                            <span class="meta-val"><%= incident.getReporterName() %></span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Assigned Analyst</span>
                            <span class="meta-val" style="color: var(--cobalt-primary);">
                                <%= incident.getAssignedAnalystName() != null ? incident.getAssignedAnalystName() : "Triage Pending" %>
                            </span>
                        </li>
                        <li class="meta-item">
                            <span class="meta-label">Created At</span>
                            <span class="meta-val" style="font-size: 0.8rem;">
                                <%= incident.getCreatedAt() != null ? incident.getCreatedAt().toString().substring(0, 19) : "" %>
                            </span>
                        </li>
                        <% if (incident.getResolvedAt() != null) { %>
                            <li class="meta-item">
                                <span class="meta-label">Resolved At</span>
                                <span class="meta-val" style="color: var(--emerald-success); font-size: 0.8rem;">
                                    <%= incident.getResolvedAt().toString().substring(0, 19) %>
                                </span>
                            </li>
                        <% } %>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <footer>
        <div class="container">
            <p>Cybersecurity Incident Reporting &amp; Management System (CIRMS)</p>
        </div>
    </footer>

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
    <script>
        function toggleRem(checkbox) {
            const label = checkbox.nextElementSibling;
            if (checkbox.checked) {
                label.classList.add('checked');
            } else {
                label.classList.remove('checked');
            }
        }
    </script>
</body>
</html>
