<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.AuditLog, com.cyberincident.dao.AdminDAO, com.cyberincident.dao.AuditLogDAO, com.cyberincident.security.ClientInfoUtil, java.util.List, java.util.Map" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || (!currentUser.isAdmin() && !currentUser.isAnalyst())) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
        return;
    }

    AdminDAO adminDAO = new AdminDAO();
    AuditLogDAO auditDAO = new AuditLogDAO();

    Map<String, Integer> kpis = adminDAO.getDashboardKPIs();
    Map<String, Integer> catStats = adminDAO.getCategoryDistribution();
    Map<String, Integer> sevStats = adminDAO.getSeverityDistribution();
    double mttr = adminDAO.getMeanTimeToResolveHours();
    List<AuditLog> auditLogs = auditDAO.getRecentLogs(100);
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports &amp; Audit Trail &bull; CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .report-section {
            margin-bottom: 30px;
        }
        .audit-timestamp {
            min-width: 175px;
            white-space: nowrap;
        }
        .audit-time-main {
            font-weight: 700;
            color: var(--text-primary);
            font-size: 0.88rem;
        }
        .audit-time-sub {
            font-size: 0.72rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
            margin-top: 2px;
        }
        .audit-device-badge {
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-sm);
            padding: 5px 10px;
            font-size: 0.82rem;
            color: var(--text-primary);
            display: inline-flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
            font-weight: 600;
        }
        .audit-ip-box {
            display: flex;
            flex-direction: column;
            gap: 3px;
            min-width: 210px;
            max-width: 320px;
        }
        .audit-ip-main {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 6px;
            background: var(--neu-surface);
            box-shadow: var(--neu-sunken-sm);
            border: var(--neu-border-subtle);
            border-radius: var(--radius-sm);
            padding: 4px 8px;
        }
        .audit-ip-code {
            font-family: var(--font-mono);
            font-size: 0.80rem;
            font-weight: 700;
            word-break: break-all;
            line-height: 1.35;
        }
        .audit-ip-code.ip-public {
            color: var(--cobalt-primary);
        }
        .audit-ip-code.ip-local {
            color: var(--text-secondary);
        }
        .btn-copy-ip {
            background: var(--neu-surface);
            border: var(--neu-border-subtle);
            box-shadow: var(--neu-raised-sm);
            cursor: pointer;
            font-size: 0.76rem;
            padding: 2px 5px;
            border-radius: 4px;
            color: var(--text-secondary);
            transition: all 0.2s ease;
            flex-shrink: 0;
        }
        .btn-copy-ip:hover {
            background: var(--cobalt-primary);
            color: #ffffff;
        }
        .audit-ip-sub {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.71rem;
            color: var(--text-muted);
        }
        .audit-ip-type {
            background: rgba(59, 130, 246, 0.12);
            color: var(--cobalt-primary);
            font-family: var(--font-mono);
            font-weight: 700;
            padding: 1px 6px;
            border-radius: 3px;
        }
        .table-wrapper {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        #auditTable {
            min-width: 1100px;
            width: 100%;
        }
        @media print {
            .navbar, .btn, footer, input {
                display: none !important;
            }
            body {
                background: #ffffff !important;
                color: #000000 !important;
            }
            .card {
                background: #ffffff !important;
                color: #000000 !important;
                border: 1px solid #ccc !important;
            }
            .cyber-table td, .cyber-table th {
                color: #000000 !important;
                border: 1px solid #ddd !important;
            }
        }
    </style>
</head>
<body>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">👑</div>
                <span>CIRMS &bull; AUDIT &amp; REPORTS</span>
            </a>
            <ul class="nav-links">
                <% if (currentUser.isAdmin()) { %>
                    <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Executive Overview</a></li>
                    <li><a href="<%= request.getContextPath() %>/admin/users.jsp">User Management</a></li>
                    <li><a href="<%= request.getContextPath() %>/admin/incidents.jsp">Master Incidents</a></li>
                <% } else { %>
                    <li><a href="<%= request.getContextPath() %>/analyst/dashboard.jsp">Triage Queue</a></li>
                <% } %>
                <li><a href="<%= request.getContextPath() %>/admin/reports.jsp" class="active">Reports &amp; Audit</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; color: var(--text-primary); font-weight: 600;"><%= currentUser.getFullName() %></span>
                <span class="role-badge <%= currentUser.getRole().toLowerCase() %>"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 12px;">
            <div>
                <h1 style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">Security Analytics, Compliance &amp; Audit Trail</h1>
                <p style="color: var(--text-secondary); font-size: 0.92rem;">
                    Executive compliance telemetry, user authentication audit, accurate device IP tracking, and India Standard Time (IST) chronology.
                </p>
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button type="button" onclick="window.print()" class="btn btn-secondary">
                    🖨️ Print / Save PDF
                </button>
                <a href="<%= request.getContextPath() %>/ReportServlet?format=csv" class="btn btn-primary">
                    📊 Export Incidents CSV
                </a>
                <a href="<%= request.getContextPath() %>/ReportServlet?format=audit_csv" class="btn btn-secondary">
                    🔒 Export Audit Log CSV
                </a>
            </div>
        </div>

        <!-- Summary Metric Cards -->
        <div class="grid-kpi">
            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Cumulative Incidents</div>
                    <div class="kpi-value"><%= kpis.getOrDefault("totalIncidents", 0) %></div>
                </div>
                <div class="kpi-icon" style="color: var(--cobalt-primary);">📁</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Mean Time to Resolve (MTTR)</div>
                    <div class="kpi-value" style="color: var(--cobalt-primary); font-size: 1.8rem;"><%= mttr %> <span style="font-size: 0.85rem; color: var(--text-secondary);">hrs</span></div>
                </div>
                <div class="kpi-icon" style="color: var(--amber-warning);">⚡</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Total Audit Events Recorded</div>
                    <div class="kpi-value" style="color: var(--emerald-safe);"><%= kpis.getOrDefault("totalAuditEvents", 0) %></div>
                </div>
                <div class="kpi-icon" style="color: var(--emerald-safe);">📜</div>
            </div>
        </div>

        <!-- Immutable Audit Log Table -->
        <div class="card report-section">
            <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                <div class="card-title">
                    <span>🔒</span>
                    <span>Security Audit Logs (Latest 100 Actions)</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">Timezone: 🇮🇳 IST (UTC+5:30)</span>
                    <input type="text" data-table-search="auditTable" class="form-control" placeholder="Search actor, IP, device, action..." style="width: 250px; padding: 6px 12px; font-size: 0.85rem;">
                </div>
            </div>

            <div class="table-wrapper">
                <table class="cyber-table" id="auditTable">
                    <thead>
                        <tr>
                            <th style="width: 75px;">Log ID</th>
                            <th style="width: 195px;">Time &amp; Date (IST - India)</th>
                            <th style="width: 140px;">Actor / Username</th>
                            <th style="width: 130px;">Security Action</th>
                            <th style="width: 180px;">Device &amp; Platform</th>
                            <th style="width: 230px;">Particular Device IP</th>
                            <th style="width: 90px;">Entity</th>
                            <th>Event Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% for (AuditLog log : auditLogs) { %>
                            <%
                                String actionName = log.getAction() != null ? log.getAction() : "";
                                String badgeStyle = "badge-review";
                                if (actionName.contains("LOGIN") && !actionName.contains("FAILED")) {
                                    badgeStyle = "badge-low"; // emerald
                                } else if (actionName.contains("FAILED") || actionName.contains("DELETED") || actionName.contains("THREAT")) {
                                    badgeStyle = "badge-critical"; // rose
                                } else if (actionName.contains("ROLE") || actionName.contains("STATUS")) {
                                    badgeStyle = "badge-high"; // amber
                                } else if (actionName.contains("REPORTED")) {
                                    badgeStyle = "badge-critical";
                                }

                                String rawIp = log.getIpAddress();
                                String displayIp = ClientInfoUtil.formatDisplayIp(rawIp);
                                boolean isLocalIp = displayIp.contains("Localhost") || displayIp.equals("127.0.0.1");
                                String ipType = ClientInfoUtil.getIpType(rawIp);

                                String deviceStr = log.getDevice();
                                if (deviceStr == null || deviceStr.trim().isEmpty()) {
                                    deviceStr = "💻 Desktop • Web Browser";
                                }
                            %>
                            <tr>
                                <td style="font-family: var(--font-mono); color: var(--text-muted); font-weight: 700;">#<%= log.getId() %></td>
                                <td class="audit-timestamp">
                                    <div class="audit-time-main">
                                        <%= ClientInfoUtil.formatIndiaTimestamp(log.getTimestamp()) %>
                                    </div>
                                    <div class="audit-time-sub">
                                        Server UTC: <%= log.getTimestamp() != null ? log.getTimestamp().toString().substring(0, 19) : "" %>
                                    </div>
                                </td>
                                <td>
                                    <span style="font-weight: 800; color: var(--text-primary); font-size: 0.92rem;"><%= log.getUsername() %></span>
                                    <% if (log.getUserId() != null && log.getUserId() > 0) { %>
                                        <span style="display: block; font-size: 0.72rem; color: var(--text-muted);">UID: #<%= log.getUserId() %></span>
                                    <% } %>
                                </td>
                                <td>
                                    <span class="badge <%= badgeStyle %>" style="font-size: 0.74rem; font-weight: 700; padding: 4px 8px;">
                                        <%= actionName %>
                                    </span>
                                </td>
                                <td>
                                    <div class="audit-device-badge">
                                        <%= deviceStr %>
                                    </div>
                                </td>
                                <td>
                                    <div class="audit-ip-box">
                                        <div class="audit-ip-main">
                                            <span class="audit-ip-code <%= isLocalIp ? "ip-local" : "ip-public" %>" title="<%= displayIp %>">
                                                <%= isLocalIp ? "🖥️ " : "🌐 " %><%= displayIp %>
                                            </span>
                                            <button type="button" class="btn-copy-ip" onclick="copyIpAddress('<%= displayIp %>', this)" title="Copy Exact Device IP">
                                                📋
                                            </button>
                                        </div>
                                        <div class="audit-ip-sub">
                                            <span class="audit-ip-type"><%= ipType %></span>
                                            <span><%= isLocalIp ? "Host Loopback" : "🇮🇳 Device Address" %></span>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <span style="font-size: 0.8rem; color: var(--text-secondary); font-weight: 600;">
                                        <%= log.getEntityType() %> <%= log.getEntityId() != null ? "#" + log.getEntityId() : "" %>
                                    </span>
                                </td>
                                <td style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                                    <%= log.getDetails() != null ? log.getDetails() : "" %>
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
            <p>Cybersecurity Incident Reporting &amp; Management System (CIRMS) &bull; Compliance &amp; Forensic Auditing</p>
        </div>
    </footer>

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
    <script>
        function copyIpAddress(ip, btn) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(ip).then(function() {
                    var original = btn.innerText;
                    btn.innerText = '✓';
                    setTimeout(function() { btn.innerText = original; }, 1400);
                }).catch(function() {
                    prompt("Copy Device IP Address:", ip);
                });
            } else {
                prompt("Copy Device IP Address:", ip);
            }
        }
    </script>
</body>
</html>
