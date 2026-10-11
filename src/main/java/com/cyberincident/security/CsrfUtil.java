package com.cyberincident.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Enterprise CSRF Defense Utility using Cryptographically Secure Anti-CSRF Synchronizer Tokens.
 */
public class CsrfUtil {

    public static final String CSRF_SESSION_ATTR = "CSRF_TOKEN";
    public static final String CSRF_PARAM_NAME = "csrf_token";
    public static final String CSRF_HEADER_NAME = "X-CSRF-Token";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Gets or generates a fresh CSRF token for the session.
     */
    public static String getOrCreateToken(HttpSession session) {
        if (session == null) return "";
        synchronized (session) {
            String token = (String) session.getAttribute(CSRF_SESSION_ATTR);
            if (token == null || token.trim().isEmpty()) {
                byte[] bytes = new byte[32];
                RANDOM.nextBytes(bytes);
                token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
                session.setAttribute(CSRF_SESSION_ATTR, token);
            }
            return token;
        }
    }

    /**
     * Validates incoming request CSRF token against session token.
     */
    public static boolean isValidToken(HttpServletRequest request) {
        if (request == null) return false;
        HttpSession session = request.getSession(false);
        if (session == null) return false;

        String sessionToken = (String) session.getAttribute(CSRF_SESSION_ATTR);
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            return false;
        }

        // Check request parameter
        String paramToken = request.getParameter(CSRF_PARAM_NAME);
        if (paramToken == null || paramToken.trim().isEmpty()) {
            // Check request header (for AJAX / Fetch calls)
            paramToken = request.getHeader(CSRF_HEADER_NAME);
        }

        if (paramToken == null || paramToken.trim().isEmpty()) {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        return java.security.MessageDigest.isEqual(
                sessionToken.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                paramToken.trim().getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }
}
