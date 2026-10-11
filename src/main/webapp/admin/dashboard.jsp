<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.dao.AdminDAO, com.cyberincident.dao.IncidentDAO, java.util.List, java.util.Map" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || !currentUser.isAdmin()) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized: Admin clearance required");
        return;
    }

    AdminDAO adminDAO = new AdminDAO();
    IncidentDAO incidentDAO = new IncidentDAO();

    Map<String, Integer> kpis = adminDAO.getDashboardKPIs();
    Map<String, Integer> catStats = adminDAO.getCategoryDistribution();
    Map<String, Integer> sevStats = adminDAO.getSeverityDistribution();
    Map<String, Integer> statusStats = adminDAO.getStatusDistribution();
    double mttr = adminDAO.getMeanTimeToResolveHours();
    List<Incident> recentIncidents = incidentDAO.getAllIncidents();
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive SOC Command Center - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .chart-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }
        .bar-container {
            margin-bottom: 12px;
        }
        .bar-label-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.82rem;
            color: var(--text-muted);
            margin-bottom: 4px;
        }
        .bar-track {
            height: 10px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 5px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.4s ease;
        }
    </style>
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">👑</div>
                <span>CIRMS &bull; EXECUTIVE SOC</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp" class="active">Executive Overview</a></li>
                <li><a href="<%= request.getContextPath() %>/scanner.jsp">🔍 Link &amp; QR Scanner</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/users.jsp">User Management</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/incidents.jsp">Master Incidents</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/reports.jsp">Reports &amp; Audit</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge admin"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;">
            <div>
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">Chief Information Security Officer &bull; Command Center</h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Enterprise cyber threat posture, SOC analyst workload, MTTD / MTTR metrics and compliance audit.
                </p>
            </div>
            <div style="display: flex; gap: 10px;">
                <a href="<%= request.getContextPath() %>/ReportServlet?format=csv" class="btn btn-secondary">
                    📊 Download Incidents CSV
                </a>
                <a href="<%= request.getContextPath() %>/ReportServlet?format=audit_csv" class="btn btn-secondary">
                    🔒 Export Audit Logs
                </a>
            </div>
        </div>

        <%
            int crit = kpis.getOrDefault("criticalThreats", 0);
            int act = kpis.getOrDefault("activeIncidents", 0);
        %>
        <!-- Threat Condition DEFCON Banner -->
        <div class="defcon-banner" style="<%= crit > 0 ? "border-color: rgba(220, 38, 38, 0.4);" : (act > 0 ? "border-color: rgba(217, 119, 6, 0.4);" : "border-color: rgba(5, 150, 105, 0.4);") %>">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span class="defcon-pulse" style="<%= crit > 0 ? "" : (act > 0 ? "background-color: var(--amber-warning); box-shadow: 0 0 6px rgba(217, 119, 6, 0.6);" : "background-color: var(--emerald-safe); box-shadow: 0 0 6px rgba(5, 150, 105, 0.6);") %>"></span>
                <div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem; font-weight: 800; letter-spacing: 0.5px;">
                        <%= crit > 0 ? "THREAT CONDITION: DEFCON 1 (CRITICAL)" : (act > 0 ? "THREAT CONDITION: DEFCON 3 (ELEVATED ALERT)" : "THREAT CONDITION: DEFCON 5 (ALL SYSTEMS SECURE)") %>
                    </strong>
                    <div style="font-size: 0.82rem; color: var(--text-secondary);">
                        <%= crit > 0 ? "Immediate containment mandated. " + crit + " active critical incident(s) requiring tier-3 incident responder dispatch." : (act > 0 ? act + " active incident(s) under forensic review and network containment." : "No critical active perimeter breaches detected.") %>
                    </div>
                </div>
            </div>
            <span class="badge <%= crit > 0 ? "badge-critical" : (act > 0 ? "badge-review" : "badge-resolved") %>" style="font-size: 0.82rem; padding: 6px 12px;">
                <%= crit > 0 ? "EMERGENCY PROTOCOL" : (act > 0 ? "SOC ACTIVE" : "NORMAL POSTURE") %>
            </span>
        </div>

        <!-- KPI Grid -->
        <div class="grid-kpi">
            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Total Incidents</div>
                    <div class="kpi-value"><%= kpis.getOrDefault("totalIncidents", 0) %></div>
                </div>
                <div class="kpi-icon" style="color: var(--cobalt-primary);">📂</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Active / Triaging</div>
                    <div class="kpi-value" style="color: #f59e0b;"><%= kpis.getOrDefault("activeIncidents", 0) %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b;">⏳</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Critical Unresolved P1</div>
                    <div class="kpi-value" style="color: #f43f5e;"><%= kpis.getOrDefault("criticalThreats", 0) %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(244, 63, 94, 0.15); color: #f43f5e;">🚨</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Resolved / Closed</div>
                    <div class="kpi-value" style="color: #10b981;"><%= kpis.getOrDefault("resolvedIncidents", 0) %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(16, 185, 129, 0.15); color: #10b981;">✅</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Mean Time to Resolve (MTTR)</div>
                    <div class="kpi-value" style="color: var(--cyan-accent); font-size: 1.8rem;"><%= mttr %> <span style="font-size: 0.9rem;">hours</span></div>
                </div>
                <div class="kpi-icon" style="background: rgba(0, 240, 255, 0.15); color: var(--cyan-accent);">⚡</div>
            </div>
        </div>

        <!-- Distribution Charts Section -->
        <div class="chart-row">
            <!-- Threat Category Distribution -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>🎯</span>
                        <span>Threat Category Distribution</span>
                    </div>
                </div>
                <div>
                    <% 
                        int totalIncs = Math.max(1, kpis.getOrDefault("totalIncidents", 1));
                        for (Map.Entry<String, Integer> entry : catStats.entrySet()) {
                            int pct = (int) Math.round((entry.getValue() * 100.0) / totalIncs);
                    %>
                        <div class="bar-container">
                            <div class="bar-label-row">
                                <span style="color: var(--text-primary); font-weight: 600;"><%= entry.getKey() %></span>
                                <span style="font-weight: 700; color: var(--text-secondary);"><%= entry.getValue() %> (<%= pct %>%)</span>
                            </div>
                            <div class="bar-track">
                                <div class="bar-fill" style="width: <%= pct %>%; background: var(--cobalt-primary);"></div>
                            </div>
                        </div>
                    <% } %>
                </div>
            </div>

            <!-- Severity Distribution -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <span>🔥</span>
                        <span>Severity Classification</span>
                    </div>
                </div>
                <div>
                    <% 
                        for (Map.Entry<String, Integer> entry : sevStats.entrySet()) {
                            int pct = (int) Math.round((entry.getValue() * 100.0) / totalIncs);
                            String color = "var(--cobalt-primary)";
                            if ("CRITICAL".equalsIgnoreCase(entry.getKey())) color = "var(--rose-danger)";
                            else if ("HIGH".equalsIgnoreCase(entry.getKey())) color = "#ea580c";
                            else if ("MEDIUM".equalsIgnoreCase(entry.getKey())) color = "var(--amber-warning)";
                    %>
                        <div class="bar-container">
                            <div class="bar-label-row">
                                <span style="color: var(--text-primary); font-weight: 600;"><%= entry.getKey() %></span>
                                <span style="font-weight: 700; color: var(--text-secondary);"><%= entry.getValue() %> (<%= pct %>%)</span>
                            </div>
                            <div class="bar-track">
                                <div class="bar-fill" style="width: <%= pct %>%; background: <%= color %>;"></div>
                            </div>
                        </div>
                    <% } %>
                </div>
            </div>
        </div>

        <!-- Master Incident Inventory Preview -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span>📋</span>
                    <span>Master Incident Repository</span>
                </div>
                <a href="<%= request.getContextPath() %>/admin/incidents.jsp" class="btn btn-secondary" style="padding: 6px 14px; font-size: 0.85rem;">
                    Manage All Incidents →
                </a>
            </div>

            <div class="table-wrapper">
                <table class="cyber-table">
                    <thead>
                        <tr>
                            <th>Incident Code</th>
                            <th>Title &amp; Target</th>
                            <th>Category</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Assigned Lead</th>
                            <th>Reported By</th>
                            <th>Date</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% for (Incident inc : recentIncidents) { %>
                            <tr>
                                <td>
                                    <span class="incident-code"><%= inc.getIncidentCode() %></span>
                                </td>
                                <td>
                                    <div style="font-weight: 700; color: var(--text-primary);"><%= inc.getTitle() %></div>
                                    <div style="font-size: 0.78rem; color: var(--text-muted);"><%= inc.getAffectedSystem() %></div>
                                </td>
                                <td><%= inc.getCategory() %></td>
                                <td>
                                    <span class="badge <%= inc.getSeverityBadgeClass() %>">
                                        <%= inc.getSeverity() %>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge <%= inc.getStatusBadgeClass() %>">
                                        <%= inc.getStatus() %>
                                    </span>
                                </td>
                                <td style="font-size: 0.85rem; color: var(--cyan-accent);">
                                    <%= inc.getAssignedAnalystName() != null ? inc.getAssignedAnalystName() : "<span style='color: var(--text-dark);'>Unassigned</span>" %>
                                </td>
                                <td style="font-size: 0.85rem; color: var(--text-muted);"><%= inc.getReporterName() %></td>
                                <td style="font-size: 0.82rem; color: var(--text-dark);">
                                    <%= inc.getCreatedAt() != null ? inc.getCreatedAt().toString().substring(0, 10) : "" %>
                                </td>
                                <td>
                                    <a href="<%= request.getContextPath() %>/IncidentServlet?action=investigate&id=<%= inc.getId() %>" class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.8rem;">
                                        Inspect
                                    </a>
                                </td>
                            </tr>
                        <% } %>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <jsp:include page="/includes/footer.jsp" />

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
</body>
</html>
