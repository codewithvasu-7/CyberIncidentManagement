package com.cyberincident.controller;

import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.dao.IncidentDAO;
import com.cyberincident.dao.UserDAO;
import com.cyberincident.model.Incident;
import com.cyberincident.model.IncidentUpdate;
import com.cyberincident.model.User;
import com.cyberincident.security.IncidentForensicEngine;
import com.cyberincident.security.ResponseEngine;
import com.cyberincident.security.RiskCalculator;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.List;

/**
 * Controller handling incident creation, lifecycle transitions,
 * triage, investigation notes, and risk updates.
 */
@WebServlet("/IncidentServlet")
public class IncidentServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final IncidentDAO incidentDAO = new IncidentDAO();
    private final UserDAO userDAO = new UserDAO();
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String action = request.getParameter("action");
        if (action == null) action = "list";

        HttpSession session = request.getSession(false);
        User currentUser = (session != null) ? (User) session.getAttribute("user") : null;
        if (currentUser == null) {
            response.sendRedirect(request.getContextPath() + "/login.jsp");
            return;
        }

        switch (action) {
            case "view":
                viewIncident(request, response, currentUser);
                break;
            case "investigate":
                investigateIncident(request, response, currentUser);
                break;
            case "list":
            default:
                listIncidents(request, response, currentUser);
                break;
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String action = request.getParameter("action");
        if (action == null) action = "report";

        HttpSession session = request.getSession(false);
        User currentUser = (session != null) ? (User) session.getAttribute("user") : null;
        if (currentUser == null) {
            response.sendRedirect(request.getContextPath() + "/login.jsp");
            return;
        }

        // DVWA CSRF Attack Defense: Validate CSRF synchronizer token for all state mutations
        if (!com.cyberincident.security.CsrfUtil.isValidToken(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Security Violation: Invalid or Missing CSRF Token (Anti-CSRF Protection)");
            return;
        }

        switch (action) {
            case "report":
                handleReport(request, response, currentUser);
                break;
            case "updateStatus":
                if (!currentUser.isAnalyst() && !currentUser.isAdmin()) {
                    response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized: Analyst or Admin role required");
                    return;
                }
                handleStatusUpdate(request, response, currentUser);
                break;
            case "updateInvestigation":
                if (!currentUser.isAnalyst() && !currentUser.isAdmin()) {
                    response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized: Analyst or Admin role required");
                    return;
                }
                handleInvestigationUpdate(request, response, currentUser);
                break;
            case "assign":
                if (!currentUser.isAnalyst() && !currentUser.isAdmin()) {
                    response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized: Analyst or Admin role required");
                    return;
                }
                handleAssignAnalyst(request, response, currentUser);
                break;
            case "addNote":
                handleAddNote(request, response, currentUser);
                break;
            default:
                response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=list");
                break;
        }
    }

    private void handleReport(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        String title = request.getParameter("title");
        String description = request.getParameter("description");
        String category = request.getParameter("category");
        String affectedSystem = request.getParameter("affectedSystem");
        String impactScope = request.getParameter("impactScope");
        String dataSensitivity = request.getParameter("dataSensitivity");
        String userSeverity = request.getParameter("severity");
        String iocIndicators = request.getParameter("iocIndicators");

        if (title == null || title.trim().isEmpty() ||
            description == null || description.trim().isEmpty() ||
            category == null || category.trim().isEmpty() ||
            affectedSystem == null || affectedSystem.trim().isEmpty()) {

            request.setAttribute("error", "Please provide Title, Category, Affected System, and Description.");
            request.getRequestDispatcher("/user/report.jsp").forward(request, response);
            return;
        }

        if (impactScope == null || impactScope.trim().isEmpty()) impactScope = "Department";
        if (dataSensitivity == null || dataSensitivity.trim().isEmpty()) dataSensitivity = "Internal";

        // Quantitative Risk Calculation via Security Engine
        RiskCalculator.RiskAssessment assessment = RiskCalculator.calculate(category, affectedSystem, impactScope, dataSensitivity);
        int calculatedScore = assessment.getScore();
        String calculatedRiskLevel = assessment.getLevel();

        String finalSeverity = (userSeverity != null && !userSeverity.trim().isEmpty())
                ? userSeverity.trim().toUpperCase()
                : RiskCalculator.getRecommendedSeverity(calculatedScore);

        // Synthesize dynamic containment & recommended response plan
        ResponseEngine.ResponsePlan responsePlan = ResponseEngine.generatePlaybook(category, calculatedRiskLevel, affectedSystem);

        Incident incident = new Incident();
        incident.setIncidentCode(incidentDAO.generateNextIncidentCode());
        incident.setTitle(title.trim());
        incident.setDescription(description.trim());
        incident.setCategory(category.trim());
        incident.setSeverity(finalSeverity);
        incident.setStatus("REPORTED");
        incident.setReporterId(user.getId());
        incident.setReporterName(user.getFullName());
        incident.setAffectedSystem(affectedSystem.trim());
        incident.setImpactScope(impactScope.trim());
        incident.setDataSensitivity(dataSensitivity.trim());
        incident.setRiskScore(calculatedScore);
        incident.setRiskLevel(calculatedRiskLevel);
        incident.setRecommendedAction(responsePlan.getRecommendedAction());
        incident.setContainmentPlan(responsePlan.getContainmentPlan());
        incident.setIocIndicators(iocIndicators != null ? iocIndicators.trim() : null);

        // Run Deep Cyber Incident Forensic Engine (URL Detonation, Attack Vector, Data Exposure & Emergency Plan)
        IncidentForensicEngine.ForensicResult forensicResult = IncidentForensicEngine.diagnose(incident);

        boolean success = incidentDAO.createIncident(incident);

        if (success) {
            // Initial triage timeline entry
            IncidentUpdate initialUpdate = new IncidentUpdate(
                    incident.getId(),
                    user.getId(),
                    user.getFullName(),
                    user.getRole(),
                    "REPORTED",
                    "Incident submitted for SOC triage. Risk Score calculated: " + incident.getRiskScore() + " (" + incident.getRiskLevel() + "). Attack Vector: " + forensicResult.getAttackVector(),
                    "Automated response playbook assigned."
            );
            incidentDAO.addIncidentUpdate(initialUpdate);

            // Forensic Engine Timeline Entry with actionable diagnostics
            String forensicNotes = "Automated CIRMS Forensic Investigation Complete: Attack Vector identified as [" + forensicResult.getAttackVector() + "]. "
                    + (forensicResult.isLinkAnalyzed() ? ("Detonated link host: " + forensicResult.getTargetDomain() + " (Threat Risk: " + incident.getRiskScore() + "). ") : "")
                    + "Personal remediation roadmap & compromised data assessment compiled.";
            IncidentUpdate forensicUpdate = new IncidentUpdate(
                    incident.getId(),
                    user.getId(),
                    "CIRMS Forensic AI Desk",
                    "ANALYST",
                    "INVESTIGATING",
                    forensicNotes,
                    "Forensic Resolution & Emergency Action Dossier generated."
            );
            incidentDAO.addIncidentUpdate(forensicUpdate);

            // Update incident status to INVESTIGATING now that automated forensics is completed
            incidentDAO.updateStatusAndSeverity(incident.getId(), "INVESTIGATING", incident.getSeverity());

            String userIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
            String userDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
            auditDAO.log(user.getId(), user.getUsername(), "INCIDENT_REPORTED", "INCIDENT", incident.getId(),
                    userIp, userDev, "Incident " + incident.getIncidentCode() + " reported: " + incident.getTitle() + " [Vector: " + forensicResult.getAttackVector() + "]");

            response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=view&id=" + incident.getId() + "&created=true");
        } else {
            request.setAttribute("error", "Database error occurred while submitting incident.");
            request.getRequestDispatcher("/user/report.jsp").forward(request, response);
        }
    }

    private void viewIncident(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        int id = parseId(request.getParameter("id"));
        Incident incident = incidentDAO.getIncidentById(id);

        if (incident == null) {
            response.sendRedirect(request.getContextPath() + "/user/incidents.jsp?error=Incident not found");
            return;
        }

        // IDOR Protection: Normal users can only view incidents reported by their account
        if (user.isUser() && incident.getReporterId() != user.getId()) {
            response.sendRedirect(request.getContextPath() + "/user/incidents.jsp?error=Access Denied: You can only view incidents reported by your account.");
            return;
        }

        List<IncidentUpdate> updates = incidentDAO.getIncidentUpdates(id);
        request.setAttribute("incident", incident);
        request.setAttribute("updates", updates);

        request.getRequestDispatcher("/user/details.jsp").forward(request, response);
    }

    private void investigateIncident(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        if (!user.isAnalyst() && !user.isAdmin()) {
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=Unauthorized");
            return;
        }

        int id = parseId(request.getParameter("id"));
        Incident incident = incidentDAO.getIncidentById(id);

        if (incident == null) {
            response.sendRedirect(request.getContextPath() + "/analyst/dashboard.jsp?error=Incident not found");
            return;
        }

        List<IncidentUpdate> updates = incidentDAO.getIncidentUpdates(id);
        List<User> analysts = userDAO.getAnalystsList();

        request.setAttribute("incident", incident);
        request.setAttribute("updates", updates);
        request.setAttribute("analysts", analysts);

        request.getRequestDispatcher("/analyst/investigation.jsp").forward(request, response);
    }

    private void listIncidents(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        String status = request.getParameter("status");
        String severity = request.getParameter("severity");
        String category = request.getParameter("category");
        String query = request.getParameter("q");

        List<Incident> incidents = incidentDAO.filterIncidents(status, severity, category, query);
        request.setAttribute("incidents", incidents);

        if (user.isAdmin()) {
            request.getRequestDispatcher("/admin/incidents.jsp").forward(request, response);
        } else if (user.isAnalyst()) {
            request.getRequestDispatcher("/analyst/dashboard.jsp").forward(request, response);
        } else {
            request.getRequestDispatcher("/user/incidents.jsp").forward(request, response);
        }
    }

    private void handleStatusUpdate(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        int id = parseId(request.getParameter("id"));
        String newStatus = request.getParameter("status");
        String newSeverity = request.getParameter("severity");
        String notes = request.getParameter("notes");
        String actionTaken = request.getParameter("actionTaken");

        Incident inc = incidentDAO.getIncidentById(id);
        if (inc == null) {
            response.sendRedirect(request.getContextPath() + "/analyst/dashboard.jsp");
            return;
        }

        if (newSeverity == null || newSeverity.trim().isEmpty()) {
            newSeverity = inc.getSeverity();
        }

        boolean updated = incidentDAO.updateStatusAndSeverity(id, newStatus, newSeverity);
        if (updated) {
            IncidentUpdate update = new IncidentUpdate(
                    id,
                    user.getId(),
                    user.getFullName(),
                    user.getRole(),
                    newStatus,
                    notes != null && !notes.trim().isEmpty() ? notes.trim() : "Status updated to " + newStatus,
                    actionTaken != null && !actionTaken.trim().isEmpty() ? actionTaken.trim() : "Severity: " + newSeverity
            );
            incidentDAO.addIncidentUpdate(update);

            String clientIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
            String clientDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
            auditDAO.log(user.getId(), user.getUsername(), "INCIDENT_STATUS_UPDATE", "INCIDENT", id,
                    clientIp, clientDev, "Status changed to " + newStatus + ", Severity: " + newSeverity);
        }

        response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=investigate&id=" + id + "&msg=Status updated successfully");
    }

    private void handleInvestigationUpdate(HttpServletRequest request, HttpServletResponse response, User user)
            throws ServletException, IOException {

        int id = parseId(request.getParameter("id"));
        String rootCause = request.getParameter("rootCause");
        String containmentPlan = request.getParameter("containmentPlan");
        String iocIndicators = request.getParameter("iocIndicators");

        incidentDAO.updateInvestigationDetails(id, rootCause, containmentPlan, iocIndicators);

        IncidentUpdate update = new IncidentUpdate(
                id,
                user.getId(),
                user.getFullName(),
                user.getRole(),
                null,
                "Investigation findings and IOC telemetry updated.",
                "Root cause & containment details saved."
        );
        incidentDAO.addIncidentUpdate(update);

        String clientIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String clientDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
        auditDAO.log(user.getId(), user.getUsername(), "INVESTIGATION_UPDATED", "INCIDENT", id,
                clientIp, clientDev, "Forensic findings and IOCs updated");

        response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=investigate&id=" + id + "&msg=Findings saved successfully");
    }

    private void handleAssignAnalyst(HttpServletRequest request, HttpServletResponse response, User user)
            throws IOException {

        int incidentId = parseId(request.getParameter("id"));
        int analystId = parseId(request.getParameter("analystId"));

        User analyst = userDAO.getUserById(analystId);
        String analystName = (analyst != null) ? analyst.getFullName() : null;

        incidentDAO.assignAnalyst(incidentId, analystId, analystName);

        IncidentUpdate update = new IncidentUpdate(
                incidentId,
                user.getId(),
                user.getFullName(),
                user.getRole(),
                null,
                "Assigned to Lead Analyst: " + (analystName != null ? analystName : "Unassigned"),
                "SOC ownership reassigned."
        );
        incidentDAO.addIncidentUpdate(update);

        String clientIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String clientDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
        auditDAO.log(user.getId(), user.getUsername(), "INCIDENT_ASSIGNED", "INCIDENT", incidentId,
                clientIp, clientDev, "Incident assigned to " + analystName);

        response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=investigate&id=" + incidentId + "&msg=Analyst assigned");
    }

    private void handleAddNote(HttpServletRequest request, HttpServletResponse response, User user)
            throws IOException {

        int incidentId = parseId(request.getParameter("id"));
        Incident inc = incidentDAO.getIncidentById(incidentId);
        if (inc == null) {
            response.sendRedirect(request.getContextPath() + "/user/incidents.jsp");
            return;
        }

        // Normal users can only comment on their own incidents
        if (user.isUser() && inc.getReporterId() != user.getId()) {
            response.sendRedirect(request.getContextPath() + "/user/incidents.jsp?error=Access Denied");
            return;
        }

        String notes = request.getParameter("notes");
        String actionTaken = request.getParameter("actionTaken");

        if (notes != null && !notes.trim().isEmpty()) {
            IncidentUpdate update = new IncidentUpdate(
                    incidentId,
                    user.getId(),
                    user.getFullName(),
                    user.getRole(),
                    null,
                    notes.trim(),
                    actionTaken != null && !actionTaken.trim().isEmpty() ? actionTaken.trim() : "Incident comment"
            );
            incidentDAO.addIncidentUpdate(update);

            String clientIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
            String clientDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
            auditDAO.log(user.getId(), user.getUsername(), "NOTE_ADDED", "INCIDENT", incidentId,
                    clientIp, clientDev, "Comment added by " + user.getFullName());
        }

        if (user.isAnalyst() || user.isAdmin()) {
            response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=investigate&id=" + incidentId);
        } else {
            response.sendRedirect(request.getContextPath() + "/IncidentServlet?action=view&id=" + incidentId);
        }
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
