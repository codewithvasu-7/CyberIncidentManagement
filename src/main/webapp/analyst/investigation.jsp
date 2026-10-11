<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.model.IncidentUpdate, com.cyberincident.dao.IncidentDAO, com.cyberincident.dao.UserDAO, com.cyberincident.security.ClientInfoUtil, com.cyberincident.security.CsrfUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || (!currentUser.isAnalyst() && !currentUser.isAdmin())) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
        return;
    }

    Incident incident = (Incident) request.getAttribute("incident");
    List<IncidentUpdate> updates = (List<IncidentUpdate>) request.getAttribute("updates");
    List<User> analysts = (List<User>) request.getAttribute("analysts");

    if (incident == null) {
        String idStr = request.getParameter("id");
        if (idStr != null) {
            IncidentDAO dao = new IncidentDAO();
            UserDAO udao = new UserDAO();
            int id = Integer.parseInt(idStr);
            incident = dao.getIncidentById(id);
            updates = dao.getIncidentUpdates(id);
            analysts = udao.getAnalystsList();
        }
    }

    if (incident == null) {
        response.sendRedirect(request.getContextPath() + "/analyst/dashboard.jsp?error=Incident not found");
        return;
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investigate <%= incident.getIncidentCode() %> - CIRMS SOC</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .investigate-layout {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }
        @media (max-width: 960px) {
            .investigate-layout {
                grid-template-columns: 1fr;
            }
        }
        .action-box {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 20px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">🔍</div>
                <span>CIRMS &bull; SOC INVESTIGATION</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/analyst/dashboard.jsp">← Back to Queue</a></li>
                <% if (currentUser.isAdmin()) { %>
                    <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Admin SOC</a></li>
                <% } %>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge analyst"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <!-- Top bar -->
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <a href="<%= request.getContextPath() %>/analyst/dashboard.jsp" class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.85rem;">
                    ← Queue
                </a>
                <span class="incident-code" style="font-size: 1.4rem;"><%= incident.getIncidentCode() %></span>
                <span class="badge <%= incident.getSeverityBadgeClass() %>" style="font-size: 0.85rem;"><%= incident.getSeverity() %></span>
                <span class="badge <%= incident.getStatusBadgeClass() %>" style="font-size: 0.85rem;"><%= incident.getStatus() %></span>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <a href="<%= request.getContextPath() %>/ExportReportServlet?id=<%= incident.getId() %>" target="_blank" class="btn btn-primary" style="padding: 6px 14px; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 6px;">
                    📄 Export Forensic Dossier (PDF)
                </a>
                <div style="font-size: 0.85rem; color: var(--text-muted);">
                    Reported by <strong><%= incident.getReporterName() %></strong> on <%= incident.getCreatedAt() != null ? incident.getCreatedAt().toString().substring(0, 16) : "" %>
                </div>
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
        <div class="card" style="margin-bottom: 20px; padding: 16px 20px;">
            <div class="stepper-wrapper" style="margin: 10px 0;">
                <div class="stepper-step <%= stage > 1 ? "completed" : (stage == 1 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 1 ? "✓" : "1" %></div>
                    <div class="stepper-title">Reported</div>
                </div>
                <div class="stepper-step <%= stage > 2 ? "completed" : (stage == 2 ? "active" : "") %>">
                    <div class="stepper-dot"><%= stage > 2 ? "✓" : "2" %></div>
                    <div class="stepper-title">Triage Review</div>
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

        <% 
            String msg = request.getParameter("msg");
            if (msg != null) { 
        %>
            <div class="alert alert-success">
                <span>✓</span>
                <span><%= ClientInfoUtil.escapeHtml(msg) %></span>
            </div>
        <% } %>

        <div class="investigate-layout">
            <!-- Left: Investigation actions, containment findings, timeline -->
            <div style="display: flex; flex-direction: column; gap: 24px;">

                <!-- Incident Brief -->
                <div class="card">
                    <h2 style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); margin-bottom: 8px; letter-spacing: -0.01em;">
                        <%= ClientInfoUtil.escapeHtml(incident.getTitle()) %>
                    </h2>
                    <div style="display: flex; gap: 20px; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 16px; border-bottom: var(--neu-border-subtle); padding-bottom: 10px;">
                        <span>Target: <strong style="color: var(--text-primary);"><%= ClientInfoUtil.escapeHtml(incident.getAffectedSystem()) %></strong></span>
                        <span>Scope: <strong style="color: var(--text-primary);"><%= ClientInfoUtil.escapeHtml(incident.getImpactScope()) %></strong></span>
                        <span>Classification: <strong style="color: var(--text-primary);"><%= ClientInfoUtil.escapeHtml(incident.getDataSensitivity()) %></strong></span>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.94rem; line-height: 1.6; white-space: pre-wrap;">
                        <%= ClientInfoUtil.escapeHtml(incident.getDescription()) %>
                    </p>
                </div>

                <!-- Triage Control Panel: Status & Severity Lifecycle Transition -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>⚙️</span>
                            <span>SOC Lifecycle Status Transition</span>
                        </div>
                    </div>

                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST">
                        <input type="hidden" name="action" value="updateStatus">
                        <input type="hidden" name="id" value="<%= incident.getId() %>">
                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                            <div class="form-group">
                                <label class="form-label">Update Status</label>
                                <select name="status" class="form-control" required>
                                    <option value="REPORTED" <%= "REPORTED".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>REPORTED (Fresh Alert)</option>
                                    <option value="UNDER_REVIEW" <%= "UNDER_REVIEW".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>UNDER_REVIEW (Triaging)</option>
                                    <option value="INVESTIGATING" <%= "INVESTIGATING".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>INVESTIGATING (Forensics)</option>
                                    <option value="CONTAINED" <%= "CONTAINED".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>CONTAINED (Isolated)</option>
                                    <option value="RESOLVED" <%= "RESOLVED".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>RESOLVED (Threat Eradicated)</option>
                                    <option value="CLOSED" <%= "CLOSED".equalsIgnoreCase(incident.getStatus()) ? "selected" : "" %>>CLOSED (Post-Mortem Complete)</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Triage Severity</label>
                                <select name="severity" class="form-control" required>
                                    <option value="LOW" <%= "LOW".equalsIgnoreCase(incident.getSeverity()) ? "selected" : "" %>>LOW (Minor noise / spam)</option>
                                    <option value="MEDIUM" <%= "MEDIUM".equalsIgnoreCase(incident.getSeverity()) ? "selected" : "" %>>MEDIUM (Contained risk)</option>
                                    <option value="HIGH" <%= "HIGH".equalsIgnoreCase(incident.getSeverity()) ? "selected" : "" %>>HIGH (Credential / System threat)</option>
                                    <option value="CRITICAL" <%= "CRITICAL".equalsIgnoreCase(incident.getSeverity()) ? "selected" : "" %>>CRITICAL (P1 Emergency / Ransomware)</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Status Change Rationale / Transition Notes</label>
                            <input type="text" name="notes" class="form-control" placeholder="e.g. Isolated infected endpoint from VLAN; running offline AV scan." required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">SOC Action Enacted</label>
                            <input type="text" name="actionTaken" class="form-control" placeholder="e.g. Firewall rule deployed, blocked 185.220.101.44">
                        </div>

                        <button type="submit" class="btn btn-primary" style="padding: 10px 20px;">
                            Apply Status Transition →
                        </button>
                    </form>
                </div>

                <!-- Forensic Findings, Root Cause & IOC Workbench -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>🔬</span>
                            <span>Forensic Findings &amp; Root Cause Analysis</span>
                        </div>
                    </div>

                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST">
                        <input type="hidden" name="action" value="updateInvestigation">
                        <input type="hidden" name="id" value="<%= incident.getId() %>">
                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">

                        <div class="form-group">
                            <label class="form-label">Identified Root Cause</label>
                            <textarea name="rootCause" class="form-control" rows="3" placeholder="Identify the initial access vector (e.g., Unpatched Log4j CVE-2021-44228, Spear-phishing with malicious macro, Compromised third-party VPN creds)..."><%= incident.getRootCause() != null ? incident.getRootCause() : "" %></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Containment &amp; Eradication Plan</label>
                            <textarea name="containmentPlan" class="form-control" rows="3" placeholder="Document containment actions taken to mitigate threat..."><%= incident.getContainmentPlan() != null ? incident.getContainmentPlan() : "" %></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Observed Indicators of Compromise (IOCs)</label>
                            <textarea name="iocIndicators" class="form-control" rows="3" placeholder="Malicious IPs, domains, hashes (SHA-256), registry keys, URLs..."><%= incident.getIocIndicators() != null ? incident.getIocIndicators() : "" %></textarea>
                        </div>

                        <button type="submit" class="btn btn-success" style="padding: 10px 20px;">
                            💾 Save Forensic Findings
                        </button>
                    </form>
                </div>

                <!-- Incident Activity Timeline -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>⏱️</span>
                            <span>Incident Audit Timeline</span>
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
                                                <span class="role-badge <%= up.getAuthorRole().toLowerCase() %>" style="font-size: 0.7rem;">
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
                                        <p style="color: #e2e8f0; font-size: 0.9rem;"><%= ClientInfoUtil.escapeHtml(up.getNotes()) %></p>
                                        <% if (up.getActionTaken() != null && !up.getActionTaken().isEmpty()) { %>
                                            <div style="font-size: 0.8rem; color: var(--cyan-accent); margin-top: 4px;">
                                                Action: <%= ClientInfoUtil.escapeHtml(up.getActionTaken()) %>
                                            </div>
                                        <% } %>
                                    </div>
                                </div>
                            <% } %>
                        </div>
                    <% } %>

                    <!-- Add Comment -->
                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST" style="margin-top: 16px; border-top: 1px solid var(--border-color); padding-top: 16px;">
                        <input type="hidden" name="action" value="addNote">
                        <input type="hidden" name="id" value="<%= incident.getId() %>">
                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">

                        <div class="form-group">
                            <label class="form-label">Add SOC Analyst Investigation Note</label>
                            <textarea name="notes" class="form-control" rows="2" placeholder="Record telemetry analysis, sandbox detonation result, or containment check..." required></textarea>
                        </div>
                        <button type="submit" class="btn btn-secondary" style="padding: 7px 14px; font-size: 0.85rem;">
                            + Post Note
                        </button>
                    </form>
                </div>
            </div>

            <!-- Right Sidebar: Threat Triage, Lead Assignment, Playbook -->
            <div style="display: flex; flex-direction: column; gap: 20px;">
                <!-- Threat Risk Meter -->
                <div class="card" style="text-align: center;">
                    <div style="font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px;">
                        Triage Threat Score
                    </div>
                    <div style="font-size: 3.5rem; font-weight: 800; font-family: var(--font-mono); margin: 6px 0; color: <%= incident.getRiskScore() >= 85 ? "#f43f5e" : (incident.getRiskScore() >= 65 ? "#f97316" : (incident.getRiskScore() >= 40 ? "#f59e0b" : "#38bdf8")) %>;">
                        <%= incident.getRiskScore() %>
                    </div>
                    <div>
                        <span class="badge <%= incident.getSeverityBadgeClass() %>" style="font-size: 0.9rem; padding: 6px 14px;">
                            <%= incident.getRiskLevel() %> THREAT
                        </span>
                    </div>
                </div>

                <!-- Analyst Assignment -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>👤</span>
                            <span>SOC Lead Assignment</span>
                        </div>
                    </div>

                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST">
                        <input type="hidden" name="action" value="assign">
                        <input type="hidden" name="id" value="<%= incident.getId() %>">
                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">

                        <div class="form-group">
                            <label class="form-label">Assign Incident Responder</label>
                            <select name="analystId" class="form-control" required>
                                <option value="">-- Select SOC Analyst --</option>
                                <% if (analysts != null) { 
                                    for (User a : analysts) { %>
                                        <option value="<%= a.getId() %>" <%= (incident.getAssignedAnalystId() != null && incident.getAssignedAnalystId() == a.getId()) ? "selected" : "" %>>
                                            <%= a.getFullName() %> (<%= a.getRole() %>)
                                        </option>
                                <%  } 
                                } %>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-secondary" style="width: 100%; padding: 8px;">
                            Reassign Lead
                        </button>
                    </form>
                </div>

                <!-- NIST SP 800-61 Playbook Box -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span>📋</span>
                            <span>Incident Playbook</span>
                        </div>
                    </div>
                    <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.6;">
                        <pre style="font-family: inherit; white-space: pre-wrap; color: var(--text-muted);"><%= incident.getRecommendedAction() != null ? incident.getRecommendedAction() : "No automated playbook available." %></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <jsp:include page="/includes/footer.jsp" />

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
</body>
</html>
