package com.cyberincident.controller;

import com.cyberincident.dao.AdminDAO;
import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.dao.IncidentDAO;
import com.cyberincident.model.AuditLog;
import com.cyberincident.model.Incident;
import com.cyberincident.model.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Controller handling security metrics reporting and CSV export.
 */
@WebServlet("/ReportServlet")
public class ReportServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final IncidentDAO incidentDAO = new IncidentDAO();
    private final AdminDAO adminDAO = new AdminDAO();
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        User user = (session != null) ? (User) session.getAttribute("user") : null;
        if (user == null || (!user.isAdmin() && !user.isAnalyst())) {
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
            return;
        }

        String format = request.getParameter("format");
        if ("csv".equalsIgnoreCase(format)) {
            exportIncidentsCSV(response);
            return;
        } else if ("audit_csv".equalsIgnoreCase(format)) {
            exportAuditCSV(response);
            return;
        }

        // View reports page
        Map<String, Integer> kpis = adminDAO.getDashboardKPIs();
        Map<String, Integer> catStats = adminDAO.getCategoryDistribution();
        Map<String, Integer> sevStats = adminDAO.getSeverityDistribution();
        Map<String, Integer> statusStats = adminDAO.getStatusDistribution();
        double mttr = adminDAO.getMeanTimeToResolveHours();
        List<AuditLog> auditLogs = auditDAO.getRecentLogs(100);

        request.setAttribute("kpis", kpis);
        request.setAttribute("catStats", catStats);
        request.setAttribute("sevStats", sevStats);
        request.setAttribute("statusStats", statusStats);
        request.setAttribute("mttr", mttr);
        request.setAttribute("auditLogs", auditLogs);

        request.getRequestDispatcher("/admin/reports.jsp").forward(request, response);
    }

    private void exportIncidentsCSV(HttpServletResponse response) throws IOException {
        String filename = "CIRMS_Incidents_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".csv";
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        List<Incident> list = incidentDAO.getAllIncidents();
        PrintWriter out = response.getWriter();

        out.println("Incident Code,Title,Category,Severity,Status,Risk Score,Risk Level,Affected System,Reporter,Assigned Analyst,Created At,Resolved At");

        for (Incident inc : list) {
            out.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    escapeCsv(inc.getIncidentCode()),
                    escapeCsv(inc.getTitle()),
                    escapeCsv(inc.getCategory()),
                    escapeCsv(inc.getSeverity()),
                    escapeCsv(inc.getStatus()),
                    inc.getRiskScore(),
                    escapeCsv(inc.getRiskLevel()),
                    escapeCsv(inc.getAffectedSystem()),
                    escapeCsv(inc.getReporterName()),
                    escapeCsv(inc.getAssignedAnalystName() != null ? inc.getAssignedAnalystName() : "Unassigned"),
                    inc.getCreatedAt() != null ? inc.getCreatedAt().toString() : "",
                    inc.getResolvedAt() != null ? inc.getResolvedAt().toString() : "N/A"
            );
        }
        out.flush();
    }

    private void exportAuditCSV(HttpServletResponse response) throws IOException {
        String filename = "CIRMS_AuditLog_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".csv";
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        List<AuditLog> list = auditDAO.getRecentLogs(500);
        PrintWriter out = response.getWriter();

        out.println("Log ID,Timestamp,Username,Action,Entity Type,Entity ID,IP Address,Device,Details");

        for (AuditLog log : list) {
            out.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",%s,\"%s\",\"%s\",\"%s\"%n",
                    log.getId(),
                    log.getTimestamp() != null ? log.getTimestamp().toString() : "",
                    escapeCsv(log.getUsername()),
                    escapeCsv(log.getAction()),
                    escapeCsv(log.getEntityType()),
                    log.getEntityId() != null ? log.getEntityId().toString() : "N/A",
                    escapeCsv(log.getIpAddress()),
                    escapeCsv(log.getDevice()),
                    escapeCsv(log.getDetails())
            );
        }
        out.flush();
    }

    private String escapeCsv(String input) {
        if (input == null) return "";
        return input.replace("\"", "\"\"");
    }
}
