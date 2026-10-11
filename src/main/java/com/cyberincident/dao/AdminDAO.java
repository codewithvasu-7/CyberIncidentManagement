package com.cyberincident.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Data Access Object for Admin analytics, metrics, and SOC performance KPIs.
 */
public class AdminDAO {

    /**
     * Aggregates key system-wide statistics for the executive dashboard.
     */
    public Map<String, Integer> getDashboardKPIs() {
        Map<String, Integer> kpis = new HashMap<>();
        String sql = "SELECT " +
                     "  (SELECT COUNT(*) FROM incidents) AS total_incidents, " +
                     "  (SELECT COUNT(*) FROM incidents WHERE status IN ('REPORTED', 'UNDER_REVIEW', 'INVESTIGATING')) AS active_incidents, " +
                     "  (SELECT COUNT(*) FROM incidents WHERE status = 'CONTAINED') AS contained_incidents, " +
                     "  (SELECT COUNT(*) FROM incidents WHERE status IN ('RESOLVED', 'CLOSED')) AS resolved_incidents, " +
                     "  (SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL' AND status NOT IN ('RESOLVED', 'CLOSED')) AS critical_threats, " +
                     "  (SELECT COUNT(*) FROM users WHERE status = 'ACTIVE') AS active_users, " +
                     "  (SELECT COUNT(*) FROM users WHERE role = 'ANALYST') AS total_analysts, " +
                     "  (SELECT COUNT(*) FROM audit_logs) AS total_audit_events";

        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                kpis.put("totalIncidents", rs.getInt("total_incidents"));
                kpis.put("activeIncidents", rs.getInt("active_incidents"));
                kpis.put("containedIncidents", rs.getInt("contained_incidents"));
                kpis.put("resolvedIncidents", rs.getInt("resolved_incidents"));
                kpis.put("criticalThreats", rs.getInt("critical_threats"));
                kpis.put("activeUsers", rs.getInt("active_users"));
                kpis.put("totalAnalysts", rs.getInt("total_analysts"));
                kpis.put("totalAuditEvents", rs.getInt("total_audit_events"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return kpis;
    }

    /**
     * Returns distribution of incidents by category.
     */
    public Map<String, Integer> getCategoryDistribution() {
        Map<String, Integer> distribution = new LinkedHashMap<>();
        String sql = "SELECT category, COUNT(*) AS cnt FROM incidents GROUP BY category ORDER BY cnt DESC";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                distribution.put(rs.getString("category"), rs.getInt("cnt"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return distribution;
    }

    /**
     * Returns distribution of incidents by severity.
     */
    public Map<String, Integer> getSeverityDistribution() {
        Map<String, Integer> distribution = new LinkedHashMap<>();
        String sql = "SELECT severity, COUNT(*) AS cnt FROM incidents GROUP BY severity ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                distribution.put(rs.getString("severity"), rs.getInt("cnt"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return distribution;
    }

    /**
     * Returns distribution of incidents by status.
     */
    public Map<String, Integer> getStatusDistribution() {
        Map<String, Integer> distribution = new LinkedHashMap<>();
        String sql = "SELECT status, COUNT(*) AS cnt FROM incidents GROUP BY status ORDER BY FIELD(status, 'REPORTED', 'UNDER_REVIEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                distribution.put(rs.getString("status"), rs.getInt("cnt"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return distribution;
    }

    /**
     * Calculates Mean Time to Resolve (MTTR) in hours.
     */
    public double getMeanTimeToResolveHours() {
        String sql = "SELECT AVG(TIMESTAMPDIFF(HOUR, created_at, resolved_at)) AS avg_hours " +
                     "FROM incidents WHERE resolved_at IS NOT NULL";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                double avg = rs.getDouble("avg_hours");
                return Math.round(avg * 10.0) / 10.0;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0.0;
    }
}
