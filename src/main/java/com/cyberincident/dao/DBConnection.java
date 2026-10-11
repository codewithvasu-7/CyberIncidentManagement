package com.cyberincident.dao;

import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Database Connection Manager for MySQL.
 * Loads configuration from db.properties if available, or falls back to robust defaults.
 */
public class DBConnection {

    private static String dbUrl = "jdbc:mysql://localhost:3306/cyber_incident_db?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=Asia/Kolkata&characterEncoding=UTF-8";
    private static String dbUser = "root";
    private static String dbPassword = "root123"; // Standard local password on this machine

    static {
        try {
            // Load MySQL Connector/J driver class
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            try {
                // Fallback for older driver name if needed
                Class.forName("com.mysql.jdbc.Driver");
            } catch (ClassNotFoundException ex) {
                System.err.println("[DBConnection] MySQL JDBC Driver not found in classpath: " + ex.getMessage());
            }
        }

        // Try to load db.properties from classpath
        try (InputStream input = DBConnection.class.getClassLoader().getResourceAsStream("db.properties")) {
            if (input != null) {
                Properties prop = new Properties();
                prop.load(input);
                if (prop.getProperty("db.url") != null) dbUrl = prop.getProperty("db.url");
                if (prop.getProperty("db.user") != null) dbUser = prop.getProperty("db.user");
                if (prop.getProperty("db.password") != null) dbPassword = prop.getProperty("db.password");
            }
        } catch (Exception ignored) {
        }

        // Allow System properties override (e.g. -Ddb.password=mypassword)
        if (System.getProperty("db.url") != null) dbUrl = System.getProperty("db.url");
        if (System.getProperty("db.user") != null) dbUser = System.getProperty("db.user");
        if (System.getProperty("db.password") != null) dbPassword = System.getProperty("db.password");

        // Allow Cloud OS Environment Variables (Render, Docker, Railway, AWS)
        if (System.getenv("DB_URL") != null && !System.getenv("DB_URL").trim().isEmpty()) {
            dbUrl = System.getenv("DB_URL").trim();
        }
        if (System.getenv("DB_USER") != null && !System.getenv("DB_USER").trim().isEmpty()) {
            dbUser = System.getenv("DB_USER").trim();
        }
        if (System.getenv("DB_PASSWORD") != null) {
            dbPassword = System.getenv("DB_PASSWORD").trim();
        }

        // Automatic Timezone Normalization for Cloud DBs (Aiven, Render, AWS, Railway)
        // Cloud MySQL servers (Aiven) store timestamps in UTC.
        // If serverTimezone is passed as Asia/Kolkata, MySQL Connector/J shifts
        // UTC timestamps by -5:30. Setting serverTimezone=UTC ensures
        // the JDBC driver correctly interprets UTC, enabling 100% accurate India Standard Time (IST) formatting.
        if (dbUrl != null && !dbUrl.contains("localhost") && !dbUrl.contains("127.0.0.1")) {
            if (dbUrl.contains("serverTimezone=Asia/Kolkata")) {
                dbUrl = dbUrl.replace("serverTimezone=Asia/Kolkata", "serverTimezone=UTC");
            } else if (!dbUrl.contains("serverTimezone=")) {
                dbUrl += (dbUrl.contains("?") ? "&" : "?") + "serverTimezone=UTC";
            }
        }
    }

    /**
     * Gets a new JDBC Connection with automatic password fallback (root123, root, blank).
     */
    public static Connection getConnection() throws SQLException {
        try {
            return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
        } catch (SQLException e) {
            // Try fallback passwords
            String[] fallbackPasswords = {"root123", "root", "", "admin"};
            for (String pass : fallbackPasswords) {
                if (!pass.equals(dbPassword)) {
                    try {
                        Connection c = DriverManager.getConnection(dbUrl, dbUser, pass);
                        dbPassword = pass; // Cache working password
                        return c;
                    } catch (SQLException ignored) {
                    }
                }
            }
            throw e;
        }
    }

    /**
     * Helper to close Connection, Statement, and ResultSet safely.
     */
    public static void close(AutoCloseable... resources) {
        for (AutoCloseable res : resources) {
            if (res != null) {
                try {
                    res.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Diagnostic test for database connectivity.
     */
    public static boolean testConnection() {
        try (Connection conn = getConnection()) {
            return conn != null && !conn.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }

    public static String getDbUrl() {
        return dbUrl;
    }
}
