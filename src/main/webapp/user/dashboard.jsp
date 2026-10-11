<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.dao.IncidentDAO, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null) {
        response.sendRedirect(request.getContextPath() + "/login.jsp");
        return;
    }

    IncidentDAO incidentDAO = new IncidentDAO();
    List<Incident> myIncidents = incidentDAO.getIncidentsByReporter(currentUser.getId());

    int totalReported = myIncidents.size();
    int activeCount = 0;
    int resolvedCount = 0;
    for (Incident inc : myIncidents) {
        if ("RESOLVED".equalsIgnoreCase(inc.getStatus()) || "CLOSED".equalsIgnoreCase(inc.getStatus())) {
            resolvedCount++;
        } else {
            activeCount++;
        }
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Incident Dashboard - CIRMS</title>
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
                <li><a href="<%= request.getContextPath() %>/user/dashboard.jsp" class="active">Dashboard</a></li>
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
                <span class="user-name">
                    <%= currentUser.getFullName() %> (<%= currentUser.getDepartment() %>)
                </span>
                <span class="role-badge user"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger btn-sm">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 12px;">
            <div>
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">Welcome, <%= currentUser.getFullName() %></h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Enterprise Cyber Threat Notification Desk &bull; Department: <%= currentUser.getDepartment() %>
                </p>
            </div>
            <div style="display: flex; gap: 10px;">
                <a href="<%= request.getContextPath() %>/scanner.jsp" class="btn btn-secondary">
                    🔍 Scan Link / QR Code
                </a>
                <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-primary" style="padding: 10px 20px;">
                    🚨 Report Suspicious Incident
                </a>
            </div>
        </div>

        <!-- KPI Grid -->
        <div class="grid-kpi">
            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Total Reported</div>
                    <div class="kpi-value"><%= totalReported %></div>
                </div>
                <div class="kpi-icon" style="color: var(--cobalt-primary);">📂</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Active / Under Triage</div>
                    <div class="kpi-value" style="color: #f59e0b;"><%= activeCount %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b;">⏳</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Remediated &amp; Resolved</div>
                    <div class="kpi-value" style="color: #10b981;"><%= resolvedCount %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(16, 185, 129, 0.15); color: #10b981;">🛡️</div>
            </div>
        </div>

        <!-- Recent Incidents Table -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span>📋</span>
                    <span>My Reported Security Incidents</span>
                </div>
                <a href="<%= request.getContextPath() %>/user/incidents.jsp" class="btn btn-secondary" style="padding: 6px 14px; font-size: 0.85rem;">
                    View All →
                </a>
            </div>

            <% if (myIncidents.isEmpty()) { %>
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    <div style="font-size: 36px; margin-bottom: 10px;">🛡️</div>
                    <p>No cybersecurity incidents reported by your account yet.</p>
                    <p style="font-size: 0.85rem; margin-top: 4px;">If you observe suspicious emails, malicious attachments, or unauthorized access, report it immediately.</p>
                    <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-primary" style="margin-top: 16px;">
                        Report An Incident
                    </a>
                </div>
            <% } else { %>
                <div class="table-wrapper">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Incident Code</th>
                                <th>Title</th>
                                <th>Category</th>
                                <th>Target Asset</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Reported On</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% for (Incident inc : myIncidents) { %>
                                <tr>
                                    <td>
                                        <span class="incident-code"><%= inc.getIncidentCode() %></span>
                                    </td>
                                    <td style="font-weight: 500;"><%= inc.getTitle() %></td>
                                    <td><%= inc.getCategory() %></td>
                                    <td style="color: var(--text-muted);"><%= inc.getAffectedSystem() %></td>
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
                                    <td style="font-size: 0.82rem; color: var(--text-dark);">
                                        <%= inc.getCreatedAt() != null ? inc.getCreatedAt().toString().substring(0, 16) : "" %>
                                    </td>
                                    <td>
                                        <a href="<%= request.getContextPath() %>/IncidentServlet?action=view&id=<%= inc.getId() %>" class="btn btn-secondary" style="padding: 5px 10px; font-size: 0.8rem;">
                                            Details
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

    <jsp:include page="/includes/footer.jsp" />

</body>
</html>
