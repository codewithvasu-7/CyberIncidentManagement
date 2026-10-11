package com.cyberincident.controller;

import com.cyberincident.dao.IncidentDAO;
import com.cyberincident.model.Incident;
import com.cyberincident.model.IncidentUpdate;
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

/**
 * Generates an Enterprise Forensic Incident Dossier & Chain of Custody Report (Printable to PDF).
 */
@WebServlet("/ExportReportServlet")
public class ExportReportServlet extends HttpServlet {

    private final IncidentDAO incidentDAO = new IncidentDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        User currentUser = session != null ? (User) session.getAttribute("user") : null;

        if (currentUser == null) {
            response.sendRedirect(request.getContextPath() + "/login.jsp");
            return;
        }

        String incidentIdStr = request.getParameter("id");
        if (incidentIdStr == null || incidentIdStr.trim().isEmpty()) {
            response.sendRedirect(request.getContextPath() + "/user/incidents.jsp");
            return;
        }

        try {
            int incidentId = Integer.parseInt(incidentIdStr);
            Incident incident = incidentDAO.getIncidentById(incidentId);

            if (incident == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Incident record not found.");
                return;
            }

            // Normal users can only export their own incidents
            if (currentUser.isUser() && incident.getReporterId() != currentUser.getId()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: You can only export incidents filed by your account.");
                return;
            }

            List<IncidentUpdate> updates = incidentDAO.getIncidentUpdates(incidentId);

            response.setContentType("text/html;charset=UTF-8");
            PrintWriter out = response.getWriter();

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
            String generatedTime = sdf.format(new Date());

            out.println("<!DOCTYPE html>");
            out.println("<html lang='en'>");
            out.println("<head>");
            out.println("<meta charset='UTF-8'>");
            out.println("<title>FORENSIC-INCIDENT-REPORT-" + incident.getIncidentCode() + "</title>");
            out.println("<style>");
            out.println("@page { size: A4; margin: 15mm; }");
            out.println("body { font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background: #fff; color: #1a1a2e; margin: 0; padding: 25px; line-height: 1.5; font-size: 13px; }");
            out.println(".report-container { max-width: 850px; margin: 0 auto; border: 1px solid #d0d7de; padding: 35px; box-shadow: 0 4px 15px rgba(0,0,0,0.06); background: #fff; }");
            out.println(".header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0052cc; padding-bottom: 18px; margin-bottom: 20px; }");
            out.println(".soc-title { font-size: 20px; font-weight: 800; color: #0052cc; text-transform: uppercase; letter-spacing: 0.5px; }");
            out.println(".soc-sub { font-size: 11px; color: #555; text-transform: uppercase; letter-spacing: 1px; }");
            out.println(".badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }");
            out.println(".badge-critical { background: #ffebe6; color: #de350b; border: 1px solid #ffbdad; }");
            out.println(".badge-high { background: #fffae6; color: #ff8b00; border: 1px solid #ffe380; }");
            out.println(".badge-medium { background: #deebff; color: #0052cc; border: 1px solid #b3d4ff; }");
            out.println(".badge-low { background: #e3fcef; color: #006644; border: 1px solid #abf5d1; }");
            out.println(".section-title { font-size: 13px; font-weight: 700; text-transform: uppercase; color: #091e42; border-bottom: 1px solid #ebecf0; padding-bottom: 5px; margin-top: 25px; margin-bottom: 12px; }");
            out.println("table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }");
            out.println("th, td { text-align: left; padding: 8px 10px; border: 1px solid #dfe1e6; font-size: 12px; }");
            out.println("th { background-color: #f4f5f7; color: #172b4d; font-weight: 600; width: 25%; }");
            out.println(".timeline-box { border-left: 2px solid #0052cc; margin-left: 10px; padding-left: 15px; margin-bottom: 12px; }");
            out.println(".sign-grid { display: flex; justify-content: space-between; margin-top: 40px; padding-top: 20px; border-top: 1px dashed #ccc; }");
            out.println(".sign-box { width: 45%; text-align: center; }");
            out.println(".sign-line { border-bottom: 1px solid #333; height: 40px; margin-bottom: 5px; }");
            out.println(".btn-print { background: #0052cc; color: white; border: none; padding: 10px 20px; font-size: 14px; font-weight: 600; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }");
            out.println("@media print { .btn-print, .no-print { display: none !important; } body { padding: 0; } .report-container { border: none; box-shadow: none; padding: 0; } }");
            out.println("</style>");
            out.println("</head>");
            out.println("<body>");

            out.println("<div class='no-print' style='max-width:850px; margin:0 auto 15px; display:flex; justify-content:space-between; align-items:center;'>");
            out.println("  <button class='btn-print' onclick='window.print()'>🖨️ Print / Save to PDF</button>");
            out.println("  <button style='padding:10px 16px; background:#f4f5f7; border:1px solid #ccc; border-radius:5px; cursor:pointer;' onclick='window.history.back()'>← Back to Application</button>");
            out.println("</div>");

            out.println("<div class='report-container'>");
            out.println("  <div class='header'>");
            out.println("    <div>");
            out.println("      <div class='soc-title'>Cyber Incident Response Desk (SOC)</div>");
            out.println("      <div class='soc-sub'>NIST SP 800-61 Rev. 2 Forensic Incident Dossier</div>");
            out.println("    </div>");
            out.println("    <div style='text-align: right;'>");
            out.println("      <div style='font-size:12px; font-weight:bold;'>INCIDENT REF: " + incident.getIncidentCode() + "</div>");
            out.println("      <div style='font-size:10px; color:#666;'>CLASSIFICATION: RESTRICTED</div>");
            out.println("    </div>");
            out.println("  </div>");

            // Executive Summary Table
            out.println("  <div class='section-title'>1. Incident Metadata & Classification</div>");
            out.println("  <table>");
            out.println("    <tr><th>Incident Title</th><td colspan='3'><strong>" + escape(incident.getTitle()) + "</strong></td></tr>");
            out.println("    <tr><th>Category</th><td>" + incident.getCategory() + "</td><th>Severity / Risk</th><td><span class='badge badge-" + incident.getSeverity().toLowerCase() + "'>" + incident.getSeverity() + " (Score: " + incident.getRiskScore() + ")</span></td></tr>");
            out.println("    <tr><th>Current Status</th><td><strong>" + incident.getStatus() + "</strong></td><th>Reported By</th><td>" + escape(incident.getReporterName()) + "</td></tr>");
            out.println("    <tr><th>Assigned Lead</th><td>" + (incident.getAssignedAnalystName() != null ? escape(incident.getAssignedAnalystName()) : "Unassigned / SOC Queue") + "</td><th>Affected Asset</th><td>" + (incident.getAffectedSystem() != null ? escape(incident.getAffectedSystem()) : "Not Specified") + "</td></tr>");
            out.println("    <tr><th>Initial Report Time</th><td>" + incident.getCreatedAt() + "</td><th>Last Updated</th><td>" + incident.getUpdatedAt() + "</td></tr>");
            out.println("  </table>");

            // Incident Details & Root Cause
            out.println("  <div class='section-title'>2. Technical Description & Observable Artifacts</div>");
            out.println("  <div style='background:#f9fafb; border:1px solid #e1e4e8; padding:12px; border-radius:4px; margin-bottom:15px; font-size:12px;'>");
            out.println("    " + escape(incident.getDescription()).replace("\n", "<br>"));
            out.println("  </div>");

            if (incident.getRootCause() != null && !incident.getRootCause().trim().isEmpty()) {
                out.println("  <div class='section-title'>3. Forensic Investigation & Root Cause (What Happened to Victim)</div>");
                out.println("  <div style='background:#f9fafb; border:1px solid #e1e4e8; padding:12px; border-radius:4px; margin-bottom:15px; font-size:12px;'>");
                out.println("    " + escape(incident.getRootCause()).replace("\n", "<br>"));
                out.println("  </div>");
            }

            if (incident.getRecommendedAction() != null && !incident.getRecommendedAction().trim().isEmpty()) {
                out.println("  <div class='section-title'>4. Emergency Remediation Roadmap & Compromised Assets Assessment</div>");
                out.println("  <div style='background:#f9fafb; border:1px solid #e1e4e8; padding:12px; border-radius:4px; margin-bottom:15px; font-size:12px;'>");
                out.println("    " + escape(incident.getRecommendedAction()).replace("\n", "<br>"));
                out.println("  </div>");
            }

            if (incident.getContainmentPlan() != null && !incident.getContainmentPlan().trim().isEmpty()) {
                out.println("  <div class='section-title'>5. Incident Response Playbook & Perimeter Containment Measures</div>");
                out.println("  <div style='background:#f9fafb; border:1px solid #e1e4e8; padding:12px; border-radius:4px; margin-bottom:15px; font-size:12px;'>");
                out.println("    " + escape(incident.getContainmentPlan()).replace("\n", "<br>"));
                out.println("  </div>");
            }

            // Timeline & Audit Updates
            out.println("  <div class='section-title'>6. Forensic Investigation Timeline & Action Log</div>");
            if (updates.isEmpty()) {
                out.println("  <p style='color:#666; font-style:italic;'>No investigation updates recorded yet.</p>");
            } else {
                for (IncidentUpdate upd : updates) {
                    out.println("  <div class='timeline-box'>");
                    out.println("    <div style='font-size:11px; color:#555;'><strong>" + upd.getCreatedAt() + "</strong> — Action by: <strong>" + escape(upd.getAuthorName()) + "</strong> (" + upd.getAuthorRole() + ") [" + (upd.getStatusChange() != null ? upd.getStatusChange() : "NOTE") + "]</div>");
                    out.println("    <div style='font-size:12px; margin-top:3px;'><strong>Notes:</strong> " + (upd.getNotes() != null ? escape(upd.getNotes()).replace("\n", "<br>") : "N/A") + "</div>");
                    if (upd.getActionTaken() != null && !upd.getActionTaken().trim().isEmpty()) {
                        out.println("    <div style='font-size:12px; margin-top:2px; color:#0052cc;'><strong>Action Executed:</strong> " + escape(upd.getActionTaken()).replace("\n", "<br>") + "</div>");
                    }
                    out.println("  </div>");
                }
            }

            // Chain of Custody & Signatures
            out.println("  <div class='section-title'>7. Authorization & Chain of Custody Certification</div>");
            out.println("  <p style='font-size:11px; color:#555;'>This document certifies that the incident response actions documented above were executed following NIST Special Publication 800-61 Computer Security Incident Handling guidelines. Generated on " + generatedTime + " by " + escape(currentUser.getFullName()) + " (" + currentUser.getRole() + ").</p>");

            out.println("  <div class='sign-grid'>");
            out.println("    <div class='sign-box'>");
            out.println("      <div class='sign-line'></div>");
            out.println("      <div style='font-weight:bold; font-size:11px;'>SOC Incident Lead Signature</div>");
            out.println("      <div style='font-size:10px; color:#666;'>Cyber Defense Center</div>");
            out.println("    </div>");
            out.println("    <div class='sign-box'>");
            out.println("      <div class='sign-line'></div>");
            out.println("      <div style='font-weight:bold; font-size:11px;'>Chief Information Security Officer (CISO)</div>");
            out.println("      <div style='font-size:10px; color:#666;'>Enterprise Security Governance</div>");
            out.println("    </div>");
            out.println("  </div>");

            out.println("</div>");
            out.println("</body>");
            out.println("</html>");

        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Incident ID format.");
        }
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
