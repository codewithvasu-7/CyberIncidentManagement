package com.cyberincident.controller;

import com.cyberincident.dao.AuditLogDAO;
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
 * Controller handling user logout and session termination.
 */
@WebServlet("/LogoutServlet")
public class LogoutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                String ipAddress = ClientInfoUtil.getClientIp(request);
                String device = ClientInfoUtil.getDeviceDetails(request);
                auditDAO.log(user.getId(), user.getUsername(), "USER_LOGOUT", "USER", user.getId(), ipAddress, device, "User logged out from " + device);
            }
            session.invalidate();
        }
        response.sendRedirect(request.getContextPath() + "/login.jsp?msg=You have been logged out securely.");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }
}
