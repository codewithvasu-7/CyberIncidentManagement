package com.cyberincident.controller;

import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.dao.UserDAO;
import com.cyberincident.model.User;
import com.cyberincident.security.ClientInfoUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Controller handling user authentication, role-based redirect,
 * and high-fidelity audit logging with real IP and device fingerprint.
 */
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final UserDAO userDAO = new UserDAO();
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect(request.getContextPath() + "/login.jsp");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String usernameOrEmail = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Extract real IP (handling Cloudflare tunnel headers) & device platform
        String ipAddress = ClientInfoUtil.getClientIp(request);
        String device = ClientInfoUtil.getDeviceDetails(request);

        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            request.setAttribute("error", "Username and Password are required");
            request.getRequestDispatcher("/login.jsp").forward(request, response);
            return;
        }

        String usernameClean = usernameOrEmail.trim();

        // 1. Brute Force Protection (DVWA 'Brute Force' Defense)
        long ipLock = com.cyberincident.security.LoginRateLimiter.isLocked("ip:" + ipAddress);
        long userLock = com.cyberincident.security.LoginRateLimiter.isLocked("user:" + usernameClean);
        long maxLock = Math.max(ipLock, userLock);
        if (maxLock > 0) {
            auditDAO.log(null, usernameClean, "LOGIN_BLOCKED_RATELIMIT", "USER", null,
                    ipAddress, device, "Login blocked by Brute-Force Rate Limiter (" + maxLock + "s remaining)");
            request.setAttribute("error", "Account or IP temporarily locked due to repeated failed logins. Please retry after " + maxLock + " seconds.");
            request.getRequestDispatcher("/login.jsp").forward(request, response);
            return;
        }

        User user = userDAO.authenticate(usernameClean, password.trim());

        if (user != null) {
            // Reset Brute Force counter
            com.cyberincident.security.LoginRateLimiter.recordSuccess("ip:" + ipAddress);
            com.cyberincident.security.LoginRateLimiter.recordSuccess("user:" + usernameClean);

            // 2. Session Fixation Defense (DVWA 'Weak Session IDs' Defense)
            // Invalidate any existing session and generate fresh secure session ID
            HttpSession oldSession = request.getSession(false);
            if (oldSession != null) {
                oldSession.invalidate();
            }
            HttpSession session = request.getSession(true);

            // Generate CSRF token for the authenticated session
            com.cyberincident.security.CsrfUtil.getOrCreateToken(session);

            session.setAttribute("user", user);
            session.setAttribute("user_device", device);
            session.setAttribute("user_ip", ipAddress);

            auditDAO.log(user.getId(), user.getUsername(), "USER_LOGIN", "USER", user.getId(), 
                    ipAddress, device, "Successful authentication from " + device);

            String contextPath = request.getContextPath();
            if (user.isAdmin()) {
                response.sendRedirect(contextPath + "/admin/dashboard.jsp");
            } else if (user.isAnalyst()) {
                response.sendRedirect(contextPath + "/analyst/dashboard.jsp");
            } else {
                response.sendRedirect(contextPath + "/user/dashboard.jsp");
            }
        } else {
            // Record failure for Brute-Force lockout
            com.cyberincident.security.LoginRateLimiter.recordFailure("ip:" + ipAddress);
            com.cyberincident.security.LoginRateLimiter.recordFailure("user:" + usernameClean);

            auditDAO.log(null, usernameOrEmail, "LOGIN_FAILED", "USER", null, 
                    ipAddress, device, "Failed login attempt from " + device);
            request.setAttribute("error", "Invalid credentials or account is inactive");
            request.getRequestDispatcher("/login.jsp").forward(request, response);
        }
    }
}
