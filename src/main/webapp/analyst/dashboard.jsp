<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.cyberincident.model.User, com.cyberincident.model.Incident, com.cyberincident.dao.IncidentDAO, com.cyberincident.security.ClientInfoUtil, java.util.List" %>
<%
    User currentUser = (User) session.getAttribute("user");
    if (currentUser == null || (!currentUser.isAnalyst() && !currentUser.isAdmin())) {
        response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized: Analyst clearance required");
        return;
    }

    IncidentDAO incidentDAO = new IncidentDAO();
    String filterStatus = request.getParameter("status");
    String filterSeverity = request.getParameter("severity");
    String filterCategory = request.getParameter("category");
    String query = request.getParameter("q");

    List<Incident> allIncidents = incidentDAO.filterIncidents(filterStatus, filterSeverity, filterCategory, query);

    int totalQueue = allIncidents.size();
    int myAssigned = 0;
    int criticalCount = 0;
    int containedCount = 0;

    for (Incident inc : allIncidents) {
        if (inc.getAssignedAnalystId() != null && inc.getAssignedAnalystId() == currentUser.getId()) {
            myAssigned++;
        }
        if ("CRITICAL".equalsIgnoreCase(inc.getSeverity()) && !"RESOLVED".equalsIgnoreCase(inc.getStatus()) && !"CLOSED".equalsIgnoreCase(inc.getStatus())) {
            criticalCount++;
        }
        if ("CONTAINED".equalsIgnoreCase(inc.getStatus())) {
            containedCount++;
        }
    }
%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Analyst Triage Center - CIRMS</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">🔍</div>
                <span>CIRMS &bull; SOC ANALYST</span>
            </a>
            <ul class="nav-links">
                <li><a href="<%= request.getContextPath() %>/analyst/dashboard.jsp" class="active">Triage Queue</a></li>
                <li><a href="<%= request.getContextPath() %>/scanner.jsp">🔍 Link &amp; QR Scanner</a></li>
                <% if (currentUser.isAdmin()) { %>
                    <li><a href="<%= request.getContextPath() %>/admin/dashboard.jsp">Executive SOC</a></li>
                <% } %>
                <li><a href="<%= request.getContextPath() %>/user/report.jsp">+ Direct Intake</a></li>
                <li><a href="<%= request.getContextPath() %>/ReportServlet">SOC Metrics</a></li>
            </ul>
            <div class="nav-user">
                <span style="font-size: 0.88rem; font-weight: 700; color: var(--text-primary);"><%= currentUser.getFullName() %></span>
                <span class="role-badge analyst"><%= currentUser.getRole() %></span>
                <a href="<%= request.getContextPath() %>/LogoutServlet" class="btn btn-danger" style="padding: 6px 12px;">Sign Out</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 16px;">
            <div>
                <div style="display: inline-flex; align-items: center; gap: 8px; font-size: 0.76rem; font-family: var(--font-mono); color: var(--cyan-accent); background: rgba(0, 240, 255, 0.1); padding: 5px 14px; border-radius: var(--radius-pill); border: 1px solid rgba(0, 240, 255, 0.25); margin-bottom: 8px;">
                    <span style="width: 8px; height: 8px; background: #10b981; border-radius: 50%; box-shadow: 0 0 8px #10b981;"></span>
                    SOC SIEM TELEMETRY ENGINE &bull; NODE: MUMBAI-DC1 &bull; 99.98% UPTIME
                </div>
                <h1 style="font-size: 1.9rem; font-weight: 800; color: var(--text-primary); letter-spacing: -0.02em;">
                    Security Operations Center &bull; Triage Queue
                </h1>
                <p style="color: var(--text-secondary); font-size: 0.94rem;">
                    Real-time incident response workbench, telemetry verification, and containment execution.
                </p>
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <a href="<%= request.getContextPath() %>/scanner.jsp" class="btn btn-secondary">
                    🔍 Phishing Scanner
                </a>
                <a href="<%= request.getContextPath() %>/user/report.jsp" class="btn btn-primary">
                    + Direct Incident Intake
                </a>
                <a href="<%= request.getContextPath() %>/ReportServlet?format=csv" class="btn btn-secondary" title="Export CSV Audit Trail">
                    📥 CSV
                </a>
            </div>
        </div>

        <!-- Threat Condition DEFCON Banner -->
        <div class="defcon-banner">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span class="defcon-pulse"></span>
                <div>
                    <strong style="color: var(--text-primary); font-size: 0.95rem; letter-spacing: 0.5px;">
                        <%= criticalCount > 0 ? "THREAT CONDITION: DEFCON 1 (CRITICAL RED ALERT)" : (totalQueue > 0 ? "THREAT CONDITION: DEFCON 3 (ELEVATED INCIDENT FLOW)" : "THREAT CONDITION: DEFCON 5 (ALL SYSTEMS NOMINAL)") %>
                    </strong>
                    <div style="font-size: 0.82rem; color: var(--text-secondary);">
                        <%= criticalCount > 0 ? "Emergency escalation: " + criticalCount + " Critical incident(s) require active containment." : totalQueue + " incident(s) awaiting triage resolution." %>
                    </div>
                </div>
            </div>
            <span class="badge <%= criticalCount > 0 ? "badge-critical" : (totalQueue > 0 ? "badge-review" : "badge-resolved") %>" style="font-size: 0.82rem; padding: 6px 12px;">
                <%= criticalCount > 0 ? "TIER-1 DISPATCH" : "QUEUE ACTIVE" %>
            </span>
        </div>

        <!-- KPIs -->
        <div class="grid-kpi">
            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Active Incidents in Queue</div>
                    <div class="kpi-value"><%= totalQueue %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(14, 165, 233, 0.15); color: #38bdf8;">🖥️</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Assigned to Me</div>
                    <div class="kpi-value" style="color: var(--cyan-accent);"><%= myAssigned %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(0, 240, 255, 0.15); color: var(--cyan-accent);">🎯</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Critical Unresolved Alerts</div>
                    <div class="kpi-value" style="color: #f43f5e;"><%= criticalCount %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(244, 63, 94, 0.15); color: #f43f5e;">🚨</div>
            </div>

            <div class="kpi-card">
                <div>
                    <div class="kpi-label">Contained (Awaiting Remediation)</div>
                    <div class="kpi-value" style="color: #10b981;"><%= containedCount %></div>
                </div>
                <div class="kpi-icon" style="background: rgba(16, 185, 129, 0.15); color: #10b981;">🛡️</div>
            </div>
        </div>

        <!-- Threat Intelligence & MITRE ATT&CK IOC Workbench (Neumorphic Extruded Panel) -->
        <div class="card" style="margin-bottom: 28px;">
            <div class="card-header">
                <div class="card-title">
                    <span class="brand-icon" style="width:36px; height:36px; font-size:18px;">📡</span>
                    <span>Global Threat Intelligence &amp; MITRE ATT&amp;CK IOC Workbench</span>
                </div>
                <div style="font-size: 0.78rem; font-weight:700; color: #059669; display: flex; align-items: center; gap: 8px; background:var(--neu-base); padding:6px 14px; border-radius:var(--radius-pill); box-shadow:var(--neu-sunken-sm); border: var(--neu-border);">
                    <span style="width: 8px; height: 8px; background: #059669; border-radius: 50%; display: inline-block;"></span>
                    LIVE IOC FEED ACTIVE
                </div>
            </div>

            <!-- Threat Intel Ticker (Debossed Well) -->
            <div style="background: var(--neu-base); box-shadow: var(--neu-sunken); border: var(--neu-border-subtle); border-radius: var(--radius-pill); padding: 10px 18px; margin-bottom: 20px; display: flex; align-items: center; gap: 14px; overflow-x: auto;">
                <span style="font-weight: 800; font-size: 0.76rem; color: var(--cobalt-primary); white-space: nowrap; letter-spacing:0.8px;">🚨 ACTIVE CVE ADVISORIES:</span>
                <div id="threatTicker" style="display: flex; gap: 14px; font-size: 0.82rem; white-space: nowrap; color: var(--text-primary);">
                    <span>Loading global threat feeds...</span>
                </div>
            </div>

            <!-- IOC Quick Investigation Terminal -->
            <div style="display: grid; grid-template-columns: 1.2fr 2fr; gap: 20px;">
                <div style="background: var(--neu-base); box-shadow: var(--neu-flat); border: var(--neu-border); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 0.88rem; font-weight: 700; color: var(--text-primary); margin-bottom: 12px; display:flex; align-items:center; gap:8px;">
                        <span>🔬</span>
                        <span>Fast IOC / Observable Detonation</span>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="iocInput" class="form-control" placeholder="Enter IP (192.168.1.100), domain, or SHA256..." style="font-size: 0.88rem; padding: 10px 14px;">
                        <button type="button" class="btn btn-primary" onclick="lookupIOC()" style="padding: 10px 18px; font-size: 0.88rem; white-space: nowrap;">Query</button>
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 12px;">
                        Fast Chips: <span style="color:var(--cobalt-primary); font-weight:600; cursor:pointer;" onclick="document.getElementById('iocInput').value='192.168.1.100';lookupIOC();">192.168.1.100</span> &bull; <span style="color:var(--cobalt-primary); font-weight:600; cursor:pointer;" onclick="document.getElementById('iocInput').value='paypa1-security-verify.xyz';lookupIOC();">paypa1-security-verify.xyz</span>
                    </div>
                </div>

                <div id="iocResultBox" style="background: var(--neu-base); box-shadow: var(--neu-sunken); border: var(--neu-border-subtle); padding: 20px; border-radius: var(--radius-md); min-height: 100px; font-size: 0.88rem; display: flex; flex-direction: column; justify-content: center;">
                    <div style="color: var(--text-secondary); font-size: 0.86rem;">Enter an Indicator of Compromise (IP / Domain / Hash) to extract MITRE ATT&amp;CK techniques and automated containment scripts in real-time.</div>
                </div>
            </div>
        </div>

        <script>
            // Fetch live threat feed
            fetch('<%= request.getContextPath() %>/ThreatIntelServlet?action=feed')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    var ticker = document.getElementById('threatTicker');
                    if (data && data.length > 0) {
                        var html = '';
                        for (var i = 0; i < data.length; i++) {
                            var item = data[i];
                            var color = (item.severity === 'CRITICAL') ? '#dc2626' : '#d97706';
                            html += '<span style="background: var(--neu-base); box-shadow: var(--neu-raised-sm); border: var(--neu-border); padding: 4px 10px; border-radius: 6px;">' +
                                    '<strong style="color:' + color + '">[' + item.severity + '] ' + item.id + ':</strong> <span style="color:var(--text-primary); font-weight:600;">' + item.title + '</span> &bull; <em style="color:var(--text-muted)">' + item.advisory + '</em>' +
                                    '</span> ';
                        }
                        ticker.innerHTML = html;
                    }
                }).catch(function(e) { console.error(e); });

            function lookupIOC() {
                var val = document.getElementById('iocInput').value.trim();
                if (!val) return;
                var box = document.getElementById('iocResultBox');
                box.innerHTML = '<span style="color:var(--cobalt-primary); font-weight:600;">Analyzing observable across threat engines...</span>';
                
                fetch('<%= request.getContextPath() %>/ThreatIntelServlet', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'indicator=' + encodeURIComponent(val)
                })
                .then(function(res) { return res.json(); })
                .then(function(res) {
                    var cmdHtml = '';
                    if (res.containmentCommands && res.containmentCommands.length > 0) {
                        cmdHtml = '<div style="margin-top:10px; background: #0f172a; color:#38bdf8; padding:10px 14px; border-radius:8px; font-family:monospace; font-size:0.78rem; box-shadow: var(--neu-sunken);">' +
                                  '<strong style="color:#a7f3d0;">Automated Containment Rule:</strong><br>' + 
                                  res.containmentCommands.join('<br>') +
                                  '</div>';
                    }
                    var badgeClass = (res.threatScore.indexOf('MALICIOUS') !== -1 || res.threatScore.indexOf('CRITICAL') !== -1) ? 'badge-critical' : 'badge-high';
                    box.innerHTML = 
                        '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">' +
                            '<span style="font-weight:700; color:var(--text-primary);">Target: <code style="color:var(--cobalt-primary);">' + res.indicator + '</code> (' + res.type + ')</span>' +
                            '<span class="badge ' + badgeClass + '">' + res.threatScore + '</span>' +
                        '</div>' +
                        '<div style="font-size:0.82rem; color:var(--text-secondary);">' +
                            '<strong>MITRE ATT&CK:</strong> <span style="color:var(--cobalt-primary); font-weight:600;">' + res.mitreTechnique + '</span> &bull; ' +
                            '<strong>Actor:</strong> <span style="color:var(--text-primary);">' + res.actor + '</span>' +
                        '</div>' +
                        '<div style="font-size:0.84rem; color:var(--text-primary); margin-top:5px;">' +
                            '<strong>Recommended Playbook:</strong> ' + res.recommendedAction +
                        '</div>' +
                        cmdHtml;
                })
                .catch(function(err) {
                    box.innerHTML = '<span style="color:#dc2626;">Error analyzing IOC.</span>';
                });
            }
        </script>
        <div class="card">
            <div class="card-header" style="flex-wrap: wrap; gap: 14px;">
                <div class="card-title">
                    <span>⚡</span>
                    <span>Live Incident Feed</span>
                </div>

                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <form method="GET" action="<%= request.getContextPath() %>/analyst/dashboard.jsp" style="display: flex; gap: 8px;">
                        <select name="status" class="form-control" style="width: auto; padding: 7px 16px; font-size: 0.85rem; border-radius: var(--radius-pill); background: rgba(255,255,255,0.06);" onchange="this.form.submit()">
                            <option value="">Status: All</option>
                            <option value="REPORTED" <%= "REPORTED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>REPORTED</option>
                            <option value="UNDER_REVIEW" <%= "UNDER_REVIEW".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>UNDER_REVIEW</option>
                            <option value="INVESTIGATING" <%= "INVESTIGATING".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>INVESTIGATING</option>
                            <option value="CONTAINED" <%= "CONTAINED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>CONTAINED</option>
                            <option value="RESOLVED" <%= "RESOLVED".equalsIgnoreCase(filterStatus) ? "selected" : "" %>>RESOLVED</option>
                        </select>

                        <select name="severity" class="form-control" style="width: auto; padding: 7px 16px; font-size: 0.85rem; border-radius: var(--radius-pill); background: rgba(255,255,255,0.06);" onchange="this.form.submit()">
                            <option value="">Severity: All</option>
                            <option value="CRITICAL" <%= "CRITICAL".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>CRITICAL</option>
                            <option value="HIGH" <%= "HIGH".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>HIGH</option>
                            <option value="MEDIUM" <%= "MEDIUM".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>MEDIUM</option>
                            <option value="LOW" <%= "LOW".equalsIgnoreCase(filterSeverity) ? "selected" : "" %>>LOW</option>
                        </select>
                    </form>

                    <input type="text" data-table-search="analystTable" class="form-control" placeholder="Quick filter incidents..." style="width: 220px; padding: 7px 16px; font-size: 0.85rem; border-radius: var(--radius-pill);">
                </div>
            </div>

            <div class="table-wrapper">
                <table class="cyber-table" id="analystTable">
                    <thead>
                        <tr>
                            <th>Incident Code</th>
                            <th>Title &amp; Target</th>
                            <th>Category</th>
                            <th>Risk Score</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Assigned Lead</th>
                            <th>Reported By</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% for (Incident inc : allIncidents) { %>
                            <tr>
                                <td>
                                    <span class="incident-code"><%= inc.getIncidentCode() %></span>
                                </td>
                                <td>
                                    <div style="font-weight: 700; color: var(--text-primary);"><%= ClientInfoUtil.escapeHtml(inc.getTitle()) %></div>
                                    <div style="font-size: 0.78rem; color: var(--text-muted);"><%= ClientInfoUtil.escapeHtml(inc.getAffectedSystem()) %></div>
                                </td>
                                <td><%= ClientInfoUtil.escapeHtml(inc.getCategory()) %></td>
                                <td>
                                    <div class="risk-meter">
                                        <span style="font-weight: 700;"><%= inc.getRiskScore() %></span>
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
                                <td style="font-size: 0.85rem; color: var(--cyan-accent);">
                                    <%= inc.getAssignedAnalystName() != null ? ClientInfoUtil.escapeHtml(inc.getAssignedAnalystName()) : "<span style='color: var(--text-dark);'>Unassigned</span>" %>
                                </td>
                                <td style="font-size: 0.85rem; color: var(--text-muted);">
                                    <%= ClientInfoUtil.escapeHtml(inc.getReporterName()) %>
                                </td>
                                <td>
                                    <a href="<%= request.getContextPath() %>/IncidentServlet?action=investigate&id=<%= inc.getId() %>" class="btn btn-primary" style="padding: 5px 12px; font-size: 0.8rem;">
                                        Investigate →
                                    </a>
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
            <p>Cybersecurity Incident Reporting &amp; Management System (CIRMS) &bull; SOC Analyst Station</p>
        </div>
    </footer>

    <script src="<%= request.getContextPath() %>/js/script.js"></script>
</body>
</html>
