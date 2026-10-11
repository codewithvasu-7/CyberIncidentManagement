package com.cyberincident.controller;

import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.model.UrlScanResult;
import com.cyberincident.model.User;
import com.cyberincident.security.UrlSecurityScanner;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * Controller handling URL & QR Code Threat Scans.
 * Supports both traditional JSP forward and asynchronous JSON endpoints.
 */
@WebServlet("/UrlScannerServlet")
public class UrlScannerServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String url = request.getParameter("url");
        if (url != null && !url.trim().isEmpty()) {
            doPost(request, response);
        } else {
            request.getRequestDispatcher("/scanner.jsp").forward(request, response);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String targetUrl = request.getParameter("url");
        boolean isQr = "true".equalsIgnoreCase(request.getParameter("isQr"));
        boolean isAjax = "true".equalsIgnoreCase(request.getParameter("ajax")) ||
                         "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));

        UrlScanResult result = UrlSecurityScanner.scanUrl(targetUrl, isQr);

        // Security Audit Logging for High-Risk Findings
        if (result.getRiskScore() >= 40) {
            HttpSession session = request.getSession(false);
            User user = (session != null) ? (User) session.getAttribute("user") : null;
            Integer uid = (user != null) ? user.getId() : null;
            String uname = (user != null) ? user.getUsername() : "ANONYMOUS_SCANNER";

            String clientIp = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
            String clientDev = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);
            auditDAO.log(uid, uname, "URL_THREAT_DETECTED", "URL", null,
                    clientIp, clientDev,
                    "Scanned URL (" + result.getDomain() + ") classified as " + result.getThreatLevel() + " (Risk Score: " + result.getRiskScore() + ")");
        }

        if (isAjax) {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter out = response.getWriter();

            // Construct JSON response
            StringBuilder json = new StringBuilder("{");
            json.append("\"cleanUrl\":\"").append(escapeJson(result.getCleanUrl())).append("\",");
            json.append("\"domain\":\"").append(escapeJson(result.getDomain())).append("\",");
            json.append("\"protocol\":\"").append(escapeJson(result.getProtocol())).append("\",");
            json.append("\"riskScore\":").append(result.getRiskScore()).append(",");
            json.append("\"threatLevel\":\"").append(escapeJson(result.getThreatLevel())).append("\",");
            json.append("\"badgeClass\":\"").append(escapeJson(result.getBadgeClass())).append("\",");
            json.append("\"summary\":\"").append(escapeJson(result.getSummary())).append("\",");
            json.append("\"recommendedAction\":\"").append(escapeJson(result.getRecommendedAction())).append("\",");
            json.append("\"isPhishing\":").append(result.isPhishing()).append(",");
            json.append("\"isMalware\":").append(result.isMalware()).append(",");
            json.append("\"isQuishing\":").append(result.isQuishing()).append(",");
            json.append("\"virusTotalScore\":\"").append(escapeJson(result.getVirusTotalScore())).append("\",");
            json.append("\"virusTotalVerdict\":\"").append(escapeJson(result.getVirusTotalVerdict())).append("\",");
            json.append("\"abuseIpScore\":\"").append(escapeJson(result.getAbuseIpScore())).append("\",");
            json.append("\"googleSafeBrowsingVerdict\":\"").append(escapeJson(result.getGoogleSafeBrowsingVerdict())).append("\",");

            // Threats array
            json.append("\"threatIndicators\":[");
            for (int i = 0; i < result.getThreatIndicators().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(escapeJson(result.getThreatIndicators().get(i))).append("\"");
            }
            json.append("],");

            // Safety array
            json.append("\"safetyFactors\":[");
            for (int i = 0; i < result.getSafetyFactors().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(escapeJson(result.getSafetyFactors().get(i))).append("\"");
            }
            json.append("]}");

            out.print(json.toString());
            out.flush();
        } else {
            request.setAttribute("scanResult", result);
            request.setAttribute("scannedUrl", targetUrl);
            request.getRequestDispatcher("/scanner.jsp").forward(request, response);
        }
    }

    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }
}
