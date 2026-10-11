<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.dao.UserDAO, com.cyberincident.security.ClientInfoUtil, com.cyberincident.security.CsrfUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || !currentUser.isAdmin()) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
        return;
    }

    UserDAO userDAO = new UserDAO();
    List<User> userList = userDAO.getAllUsers();
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Administration &bull; CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
</head>
<body>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">👑</div>
                <span>CIRMS &bull; USER ADMIN</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Executive Overview</a></li>
                <li><a href="<%= request.getContextPath() %>/admin/users.jsp" class="active">User Management</a></li>
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
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">User Directory &amp; RBAC Control</h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Manage enterprise identities, promote security analysts, and enforce credential authorizations.
                </p>
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

        <div class="card">
            <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                <div class="card-title">
                    <span>👥</span>
                    <span>Registered System Identities (<%= userList.size() %>)</span>
                </div>
                <input type="text" data-table-search="usersTable" class="form-control" placeholder="Search by name, email, department..." style="width: 280px; padding: 6px 12px; font-size: 0.85rem;">
            </div>

            <div class="table-wrapper">
                <table class="cyber-table" id="usersTable">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Username</th>
                            <th>Full Name &amp; Email</th>
                            <th>Department</th>
                            <th>Current Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Modify Role</th>
                            <th>Toggle Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% for (User u : userList) { %>
                            <tr>
                                <td style="font-family: var(--font-mono); color: var(--text-muted);">#<%= u.getId() %></td>
                                <td style="font-weight: 700; color: var(--text-primary);"><%= u.getUsername() %></td>
                                <td>
                                    <div style="font-weight: 600; color: var(--text-primary);"><%= u.getFullName() %></div>
                                    <div style="font-size: 0.78rem; color: var(--text-muted);"><%= u.getEmail() %></div>
                                </td>
                                <td><%= u.getDepartment() %></td>
                                <td>
                                    <span class="role-badge <%= u.getRole().toLowerCase() %>">
                                        <%= u.getRole() %>
                                    </span>
                                </td>
                                <td>
                                    <% if ("ACTIVE".equalsIgnoreCase(u.getStatus())) { %>
                                        <span class="badge badge-resolved" style="font-size: 0.72rem;">ACTIVE</span>
                                    <% } else { %>
                                        <span class="badge badge-critical" style="font-size: 0.72rem;"><%= u.getStatus() %></span>
                                    <% } %>
                                </td>
                                <td style="font-size: 0.8rem; color: var(--text-dark);">
                                    <%= u.getLastLogin() != null ? u.getLastLogin().toString().substring(0, 16) : "Never" %>
                                </td>
                                <td>
                                    <form action="<%= request.getContextPath() %>/AdminServlet" method="POST" style="display: flex; gap: 4px;">
                                        <input type="hidden" name="action" value="updateRole">
                                        <input type="hidden" name="userId" value="<%= u.getId() %>">
                                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">
                                        <select name="role" class="form-control" style="padding: 4px 8px; font-size: 0.78rem; width: 95px;">
                                            <option value="USER" <%= "USER".equalsIgnoreCase(u.getRole()) ? "selected" : "" %>>USER</option>
                                            <option value="ANALYST" <%= "ANALYST".equalsIgnoreCase(u.getRole()) ? "selected" : "" %>>ANALYST</option>
                                            <option value="ADMIN" <%= "ADMIN".equalsIgnoreCase(u.getRole()) ? "selected" : "" %>>ADMIN</option>
                                        </select>
                                        <button type="submit" class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.75rem;">Set</button>
                                    </form>
                                </td>
                                <td>
                                    <form action="<%= request.getContextPath() %>/AdminServlet" method="POST" style="display: inline;">
                                        <input type="hidden" name="action" value="updateStatus">
                                        <input type="hidden" name="userId" value="<%= u.getId() %>">
                                        <input type="hidden" name="csrf_token" value="<%= CsrfUtil.getOrCreateToken(session) %>">
                                        <% if ("ACTIVE".equalsIgnoreCase(u.getStatus())) { %>
                                            <input type="hidden" name="status" value="INACTIVE">
                                            <button type="submit" class="btn btn-danger" style="padding: 4px 8px; font-size: 0.75rem;">Suspend</button>
                                        <% } else { %>
                                            <input type="hidden" name="status" value="ACTIVE">
                                            <button type="submit" class="btn btn-success" style="padding: 4px 8px; font-size: 0.75rem;">Activate</button>
                                        <% } %>
                                    </form>
                                </td>
                            </tr>
                        <% } %>
                    </tbody>
                </table>
            </div>
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
