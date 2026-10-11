<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.dao.IncidentDAO, com.cyberincident.dao.UserDAO, com.cyberincident.security.ClientInfoUtil, com.cyberincident.security.CsrfUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || !currentUser.isAdmin()) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
        return;
    }

    IncidentDAO incidentDAO = new IncidentDAO();
    UserDAO userDAO = new UserDAO();

    String filterStatus = request.getParameter("status");
    String filterSeverity = request.getParameter("severity");
    String filterCategory = request.getParameter("category");
    String query = request.getParameter("q");

    List<Incident> incidentList = incidentDAO.filterIncidents(filterStatus, filterSeverity, filterCategory, query);
    List<User> analysts = userDAO.getAnalystsList();
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Master Incident Repository &bull; CIRMS Admin</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
</head>
<body>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">👑</div>
                <span>CIRMS &bull; MASTER INCIDENTS</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Executive Overview</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/users.jsp">User Management</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/incidents.jsp" class="active">Master Incidents</a></li>
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
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">Master Incident Archive &amp; Governance</h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Full spectrum repository of enterprise incident records, triage states, and containment logs.
                </p>
            </div>
            <a href="<%= request.getContextPath() %>/ReportServlet?format=csv" class="btn btn-secondary">
                📥 Export Entire Archive (CSV)
            </a>
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

        <div class="card">
            <div class="card-header" style="flex-wrap: wrap; gap: 14px;">
                <div class="card-title">
                    <span>📑</span>
                    <span>Incidents Records (<%= incidentList.size() %>)</span>
                </div>

                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <form method="GET" action="<%= request.getContextPath() %>/admin/incidents.jsp" style="display: flex; gap: 8px;">
                        <select name="status" class="form-control" style="width: auto; padding: 6px 10px; font-size: 0.82rem;" onchange="this.form.submit()">
                            <option value="">Status: All</option>
                            <option value="REPORTED" <%= "REPORTED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>REPORTED</option>
                            <option value="UNDER_REVIEW" <%= "UNDER_REVIEW".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>UNDER_REVIEW</option>
                            <option value="INVESTIGATING" <%= "INVESTIGATING".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>INVESTIGATING</option>
                            <option value="CONTAINED" <%= "CONTAINED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>CONTAINED</option>
                            <option value="RESOLVED" <%= "RESOLVED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>RESOLVED</option>
                            <option value="CLOSED" <%= "CLOSED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>CLOSED</option>
                        </select>

                        <select name="severity" class="form-control" style="width: auto; padding: 6px 10px; font-size: 0.82rem;" onchange="this.form.submit()">
                            <option value="">Severity: All</option>
                            <option value="CRITICAL" <%= "CRITICAL".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>CRITICAL</option>
                            <option value="HIGH" <%= "HIGH".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>HIGH</option>
                            <option value="MEDIUM" <%= "MEDIUM".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>MEDIUM</option>
                            <option value="LOW" <%= "LOW".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>LOW</option>
                        </select>
                    </form>

                    <input type="text" data-table-search="masterIncidentsTable" class="form-control" placeholder="Quick search..." style="width: 200px; padding: 6px 10px; font-size: 0.85rem;">
                </div>
            </div>

            <div class="table-wrapper">
                <table class="cyber-table" id="masterIncidentsTable">
                    <thead>
                        <tr>
                            <th>Code</th>
                            <th>Title &amp; Target</th>
                            <th>Category</th>
                            <th>Score</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Reporter</th>
                            <th>Assign Analyst</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% for (Incident inc : incidentList) { %>
                            <tr>
                                <td>
                                    <span class="incident-code"><%= inc.getIncidentCode() %></span>
                                </td>
                                <td>
                                    <div style="font-weight: 700; color: var(--text-primary);"><%= ClientInfoUtil.escapeHtml(inc.getTitle()) %></div>
                                    <div style="font-size: 0.76rem; color: var(--text-muted);"><%= ClientInfoUtil.escapeHtml(inc.getAffectedSystem()) %></div>
                                </td>
                                <td><%= inc.getCategory() %></td>
                                <td>
                                    <span style="font-family: var(--font-mono); font-weight: 700; color: <%= inc.getRiskScore() >= 85 ? "var(--rose-danger)" : (inc.getRiskScore() >= 65 ? "#ea580c" : "var(--cobalt-primary)") %>;">
                                        <%= inc.getRiskScore() %>
                                    </span>
                                </td>
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
                                <td style="font-size: 0.82rem; color: var(--text-muted);"><%= ClientInfoUtil.escapeHtml(inc.getReporterName()) %></td>
                                <td>
                                    <form action="<%= request.getContextPath() %>/IncidentServlet" method="POST" style="display: flex; gap: 4px;">
                                        <input type="hidden" name="action" value="assign">
                                        <input type="hidden" name="id" value="<%= inc.getId() %>">
                                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">
                                        <select name="analystId" class="form-control" style="padding: 3px 6px; font-size: 0.76rem; width: 110px;">
                                            <option value="">-- Assign --</option>
                                            <% for (User a : analysts) { %>
                                                <option value="<%= a.getId() %>" <%= (inc.getAssignedAnalystId() != null && inc.getAssignedAnalystId() == a.getId()) ? "selected" : "" %>>
                                                    <%= a.getFullName() %>
                                                </option>
                                            <% } %>
                                        </select>
                                        <button type="submit" class="btn btn-secondary" style="padding: 3px 6px; font-size: 0.72rem;">Set</button>
                                    </form>
                                </td>
                                <td>
                                    <div style="display: flex; gap: 6px;">
                                        <a href="<%= request.getContextPath() %>/IncidentServlet?action=investigate&id=<%= inc.getId() %>" class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.75rem;">
                                            Inspect
                                        </a>
                                        <a href="<%= request.getContextPath() %>/ExportReportServlet?id=<%= inc.getId() %>" target="_blank" class="btn btn-primary" style="padding: 4px 8px; font-size: 0.75rem;">
                                            PDF
                                        </a>
                                        <form action="<%= request.getContextPath() %>/AdminServlet" method="POST" onsubmit="return confirm('Permanently delete this incident record?');" style="display: inline;">
                                            <input type="hidden" name="action" value="deleteIncident">
                                            <input type="hidden" name="incidentId" value="<%= inc.getId() %>">
                                            <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">
                                            <button type="submit" class="btn btn-danger" style="padding: 4px 8px; font-size: 0.75rem;">Delete</button>
                                        </form>
                                    </div>
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
