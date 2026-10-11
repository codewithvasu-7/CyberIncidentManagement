package com.cyberincident.controller;

import com.cyberincident.dao.AdminDAO;
import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.dao.IncidentDAO;
import com.cyberincident.dao.UserDAO;
import com.cyberincident.model.AuditLog;
import com.cyberincident.model.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Controller handling Administrator operations, user management,
 * role assignments, system-wide KPIs, and audit trail inspection.
 */
@WebServlet("/AdminServlet")
public class AdminServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final UserDAO userDAO = new UserDAO();
    private final IncidentDAO incidentDAO = new IncidentDAO();
    private final AdminDAO adminDAO = new AdminDAO();
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        User user = (session != null) ? (User) session.getAttribute("user") : null;
        if (user == null || !user.isAdmin()) {
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=Admin authorization required");
            return;
        }

        String view = request.getParameter("view");
        if (view == null) view = "dashboard";

        switch (view) {
            case "users":
                List<User> userList = userDAO.getAllUsers();
                request.setAttribute("users", userList);
                request.getRequestDispatcher("/admin/users.jsp").forward(request, response);
                break;

            case "incidents":
                request.getRequestDispatcher("/admin/incidents.jsp").forward(request, response);
                break;

            case "audit":
                List<AuditLog> logs = auditDAO.getRecentLogs(100);
                request.setAttribute("auditLogs", logs);
                request.getRequestDispatcher("/admin/reports.jsp?tab=audit").forward(request, response);
                break;

            case "dashboard":
            default:
                Map<String, Integer> kpis = adminDAO.getDashboardKPIs();
                request.setAttribute("kpis", kpis);
                request.setAttribute("categoryStats", adminDAO.getCategoryDistribution());
                request.setAttribute("severityStats", adminDAO.getSeverityDistribution());
                request.setAttribute("statusStats", adminDAO.getStatusDistribution());
                request.setAttribute("mttrHours", adminDAO.getMeanTimeToResolveHours());
                request.setAttribute("recentIncidents", incidentDAO.getAllIncidents());
                request.getRequestDispatcher("/admin/dashboard.jsp").forward(request, response);
                break;
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        User user = (session != null) ? (User) session.getAttribute("user") : null;
        if (user == null || !user.isAdmin()) {
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=Admin authorization required");
            return;
        }

        // Anti-CSRF Token Validation
        if (!com.cyberincident.security.CsrfUtil.isValidToken(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Security Violation: Invalid or Missing CSRF Token");
            return;
        }

        String action = request.getParameter("action");
        if (action == null) action = "";

        switch (action) {
            case "updateRole":
                handleUpdateRole(request, response, user);
                break;
            case "updateStatus":
                handleUpdateStatus(request, response, user);
                break;
            case "deleteIncident":
                handleDeleteIncident(request, response, user);
                break;
            default:
                response.sendRedirect(request.getContextPath() + "/AdminServlet?view=dashboard");
                break;
        }
    }

    private void handleUpdateRole(HttpServletRequest request, HttpServletResponse response, User admin)
            throws IOException {
        int targetUserId = parseId(request.getParameter("userId"));
        String newRole = request.getParameter("role");

        String adminIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String adminDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
        if (targetUserId > 0 && newRole != null) {
            userDAO.updateUserRole(targetUserId, newRole.trim().toUpperCase());
            auditDAO.log(admin.getId(), admin.getUsername(), "USER_ROLE_CHANGED", "USER", targetUserId,
                    adminIp, adminDev, "User #" + targetUserId + " role changed to " + newRole);
        }
        response.sendRedirect(request.getContextPath() + "/AdminServlet?view=users&msg=Role updated successfully");
    }

    private void handleUpdateStatus(HttpServletRequest request, HttpServletResponse response, User admin)
            throws IOException {
        int targetUserId = parseId(request.getParameter("userId"));
        String newStatus = request.getParameter("status");

        String adminIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String adminDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
        if (targetUserId > 0 && newStatus != null) {
            userDAO.updateUserStatus(targetUserId, newStatus.trim().toUpperCase());
            auditDAO.log(admin.getId(), admin.getUsername(), "USER_STATUS_CHANGED", "USER", targetUserId,
                    adminIp, adminDev, "User #" + targetUserId + " status changed to " + newStatus);
        }
        response.sendRedirect(request.getContextPath() + "/AdminServlet?view=users&msg=Status updated successfully");
    }

    private void handleDeleteIncident(HttpServletRequest request, HttpServletResponse response, User admin)
            throws IOException {
        int incidentId = parseId(request.getParameter("incidentId"));
        String adminIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String adminDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
        if (incidentId > 0) {
            incidentDAO.deleteIncident(incidentId);
            auditDAO.log(admin.getId(), admin.getUsername(), "INCIDENT_DELETED", "INCIDENT", incidentId,
                    adminIp, adminDev, "Incident #" + incidentId + " purged by Administrator");
        }
        response.sendRedirect(request.getContextPath() + "/admin/incidents.jsp?msg=Incident deleted");
    }

    private int parseId(String param) {
        if (param == null) return 0;
        try {
            return Integer.parseInt(param.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
