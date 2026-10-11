<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" isErrorPage="true" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIRMS &bull; Security Notice</title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/style.css">
    <style>
        .error-wrapper {
            min-height: calc(100vh - 160px);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px 20px;
        }
        .error-card {
            background: var(--neu-base);
            box-shadow: var(--neu-raised-lg);
            border-radius: var(--radius-xl);
            border: var(--neu-border);
            max-width: 580px;
            width: 100%;
            padding: 44px 36px;
            text-align: center;
        }
        .error-code {
            font-family: var(--font-mono);
            font-size: 3.5rem;
            font-weight: 800;
            color: var(--rose-threat);
            line-height: 1;
            margin-bottom: 12px;
            letter-spacing: -2px;
        }
        .error-title {
            font-size: 1.4rem;
            font-weight: 800;
            color: var(--text-primary);
            margin-bottom: 12px;
        }
        .error-desc {
            color: var(--text-secondary);
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 28px;
        }
        .error-actions {
            display: flex;
            justify-content: center;
            gap: 14px;
            flex-wrap: wrap;
        }
    </style>
</head>
<body>
    <div class="spatial-grid-overlay"></div>

    <nav class="navbar">
        <div class="nav-container">
            <a href="<%= request.getContextPath() %>/index.jsp" class="brand">
                <div class="brand-icon">🛡️</div>
                <span>CIRMS</span>
            </a>
            <div class="nav-user">
                <a href="<%= request.getContextPath() %>/index.jsp" class="btn btn-primary" style="padding: 6px 16px;">Platform Home</a>
            </div>
        </div>
    </nav>

    <div class="error-wrapper">
        <div class="error-card">
            <div class="error-code">
                <% 
                    Integer statusCode = (Integer) request.getAttribute("jakarta.servlet.error.status_code");
                    out.print(statusCode != null ? statusCode : 404);
                %>
            </div>
            <h2 class="error-title">Security &amp; Navigation Notice</h2>
            <p class="error-desc">
                The requested resource is either restricted by security policies, undergoing maintenance, or does not exist on this gateway.
            </p>
            <div class="error-actions">
                <a href="<%= request.getContextPath() %>/index.jsp" class="btn btn-primary" style="padding: 10px 22px;">
                    🏠 Return to Home
                </a>
                <a href="<%= request.getContextPath() %>/LoginServlet" class="btn btn-secondary" style="padding: 10px 22px;">
                    🔐 SOC Portal Login
                </a>
            </div>
        </div>
    </div>

    <!-- Reusable Enterprise Footer -->
    <jsp:include page="/includes/footer.jsp" />
</body>
</html>
