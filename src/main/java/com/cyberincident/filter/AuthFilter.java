package com.cyberincident.filter;

import com.cyberincident.model.User;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Authentication and Role-Based Authorization Filter (RBAC).
 * Guards secure endpoints (/user/*, /analyst/*, /admin/*) and prevents caching.
 */
@WebFilter(filterName = "AuthFilter", urlPatterns = {"/*"})
public class AuthFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String uri = req.getRequestURI();
        String contextPath = req.getContextPath();
        String path = uri.substring(contextPath.length());

        // Security Headers (CSP Bypass defense, Clickjacking defense, MIME-sniffing defense)
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:;");

        // Permit static assets and public endpoints
        if (isPublicPath(path)) {
            chain.doFilter(request, response);
            return;
        }

        // Prevent browser caching on secured pages
        res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setDateHeader("Expires", 0);

        HttpSession session = req.getSession(false);
        User user = (session != null) ? (User) session.getAttribute("user") : null;

        // If not logged in, redirect to login
        if (user == null) {
            res.sendRedirect(contextPath + "/login.jsp?msg=Please login to access this resource");
            return;
        }

        // Check Role-Based Access Control
        if (path.startsWith("/admin/") || path.startsWith("/AdminServlet")) {
            if (!user.isAdmin()) {
                res.sendRedirect(contextPath + "/login.jsp?error=Access Denied: Administrator role required");
                return;
            }
        } else if (path.startsWith("/analyst/")) {
            if (!user.isAnalyst() && !user.isAdmin()) {
                res.sendRedirect(contextPath + "/login.jsp?error=Access Denied: SOC Analyst role required");
                return;
            }
        } else if (path.startsWith("/user/")) {
            // Any authenticated user can access /user/
            if (user == null) {
                res.sendRedirect(contextPath + "/login.jsp");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private boolean isPublicPath(String path) {
        if (path == null || path.isEmpty() || "/".equals(path)) return true;
        return path.equals("/index.jsp") ||
               path.equals("/login.jsp") ||
               path.equals("/register.jsp") ||
               path.equals("/scanner.jsp") ||
               path.equals("/LoginServlet") ||
               path.equals("/RegisterServlet") ||
               path.equals("/LogoutServlet") ||
               path.equals("/UrlScannerServlet") ||
               path.equals("/ThreatIntelServlet") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.startsWith("/favicon.ico");
    }

    @Override
    public void destroy() {
    }
}
