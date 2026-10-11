<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.dao.IncidentDAO, com.cyberincident.security.ClientInfoUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null) {
        response.sendRedirect(request.getContextPath() + "/login.jsp");
        return;
    }

    IncidentDAO incidentDAO = new IncidentDAO();
    List<Incident> incidents = incidentDAO.getIncidentsByReporter(currentUser.getId());
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Incident History - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
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
                <li><a href="<%= request.getContextPath() %>/user/report.jsp">+ Report Incident</a></li>
                <li><a href="<%= request.getContextPath() %>/user/incidents.jsp" class="active">My Incidents</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge user"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;">
            <div>
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">My Reported Incidents</h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Chronological history of security anomalies and notifications you have submitted.
                </p>
            </div>
            <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-primary">
                + Report New Incident
            </a>
        </div>

        <div class="card">
            <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                <div class="card-title">
                    <span>📑</span>
                    <span>Incidents Registered (<%= incidents.size() %>)</span>
                </div>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <input type="text" data-table-search="userIncidentsTable" class="form-control" placeholder="Search by title, code, asset..." style="width: 260px; padding: 6px 12px; font-size: 0.88rem;">
                </div>
            </div>

            <% if (incidents.isEmpty()) { %>
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    <p>No incidents recorded.</p>
                </div>
            <% } else { %>
                <div class="table-wrapper">
                    <table class="cyber-table" id="userIncidentsTable">
                        <thead>
                            <tr>
                                <th>Incident Code</th>
                                <th>Title</th>
                                <th>Category</th>
                                <th>Target Asset</th>
                                <th>Risk Score</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Assigned Lead</th>
                                <th>Date Reported</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% for (Incident inc : incidents) { %>
                                <tr>
                                    <td>
                                        <span class="incident-code"><%= inc.getIncidentCode() %></span>
                                    </td>
                                    <td style="font-weight: 500;"><%= ClientInfoUtil.escapeHtml(inc.getTitle()) %></td>
                                    <td><%= ClientInfoUtil.escapeHtml(inc.getCategory()) %></td>
                                    <td style="color: var(--text-muted);"><%= ClientInfoUtil.escapeHtml(inc.getAffectedSystem()) %></td>
                                    <td>
                                        <div class="risk-meter">
                                            <span><%= inc.getRiskScore() %></span>
                                            <div class="risk-bar">
                                                <div class="risk-bar-fill" style="width: <%= inc.getRiskScore() %>%; background: <%= inc.getRiskScore() >= 85 ? "#f43f5e" : (inc.getRiskScore() >= 65 ? "#f97316" : (inc.getRiskScore() >= 40 ? "#f59e0b" : "#38bdf8")) %>;"></div>
                                            </div>
                                        </div>
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
                                    <td style="font-size: 0.85rem; color: var(--text-muted);">
                                        <%= inc.getAssignedAnalystName() != null ? ClientInfoUtil.escapeHtml(inc.getAssignedAnalystName()) : "Triage Pending" %>
                                    </td>
                                    <td style="font-size: 0.82rem; color: var(--text-dark);">
                                        <%= inc.getCreatedAt() != null ? inc.getCreatedAt().toString().substring(0, 16) : "" %>
                                    </td>
                                    <td>
                                        <a href="<%= request.getContextPath() %>/IncidentServlet?action=view&id=<%= inc.getId() %>" class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.8rem;">
                                            View Details
                                        </a>
                                    </td>
                                </tr>
                            <% } %>
                        </tbody>
                    </table>
                </div>
            <% } %>
        </div>
    </div>

    <footer>
        <div class="container">
            <p>Cybersecurity Incident Reporting &amp; Management System (CIRMS)</p>
        </div>
    </footer>

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
</body>
</html>
