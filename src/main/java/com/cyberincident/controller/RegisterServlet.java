package com.cyberincident.controller;

import com.cyberincident.dao.AuditLogDAO;
import com.cyberincident.dao.UserDAO;
import com.cyberincident.model.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Controller handling new user registration.
 */
@WebServlet("/RegisterServlet")
public class RegisterServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final UserDAO userDAO = new UserDAO();
    private final AuditLogDAO auditDAO = new AuditLogDAO();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect(request.getContextPath() + "/register.jsp");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        String email = request.getParameter("email");
        String fullName = request.getParameter("fullName");
        String department = request.getParameter("department");
        String password = request.getParameter("password");
        String confirmPassword = request.getParameter("confirmPassword");
        String ipAddress = com.cyberincident.security.ClientInfoUtil.getClientIp(request);
        String device = com.cyberincident.security.ClientInfoUtil.getDeviceDetails(request);

        // Validation
        if (username == null || username.trim().isEmpty() ||
            email == null || email.trim().isEmpty() ||
            fullName == null || fullName.trim().isEmpty() ||
            password == null || password.trim().isEmpty()) {
            request.setAttribute("error", "All fields marked with * are required");
            request.getRequestDispatcher("/register.jsp").forward(request, response);
            return;
        }

        if (!password.equals(confirmPassword)) {
            request.setAttribute("error", "Passwords do not match");
            request.getRequestDispatcher("/register.jsp").forward(request, response);
            return;
        }

        if (password.length() < 6) {
            request.setAttribute("error", "Password must be at least 6 characters long");
            request.getRequestDispatcher("/register.jsp").forward(request, response);
            return;
        }

        if (userDAO.userExists(username.trim(), email.trim())) {
            request.setAttribute("error", "Username or Email is already registered in the system");
            request.getRequestDispatcher("/register.jsp").forward(request, response);
            return;
        }

        User newUser = new User();
        newUser.setUsername(username.trim());
        newUser.setEmail(email.trim());
        newUser.setFullName(fullName.trim());
        newUser.setDepartment(department != null && !department.trim().isEmpty() ? department.trim() : "General Operations");
        newUser.setRole("USER");
        newUser.setStatus("ACTIVE");

        boolean created = userDAO.registerUser(newUser, password);

        if (created) {
            auditDAO.log(newUser.getId(), newUser.getUsername(), "USER_REGISTERED", "USER", newUser.getId(), ipAddress, device, "Self-registration completed from " + device);
            String encodedUser = java.net.URLEncoder.encode(newUser.getUsername(), java.nio.charset.StandardCharsets.UTF_8);
            response.sendRedirect(request.getContextPath() + "/login.jsp?success=Account created successfully! Please sign in with your credentials.&user=" + encodedUser);
        } else {
            request.setAttribute("error", "Failed to create account due to internal database error");
            request.getRequestDispatcher("/register.jsp").forward(request, response);
        }
    }
}
