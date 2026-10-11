package com.cyberincident.dao;

import com.cyberincident.model.AuditLog;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for Security Audit Logs.
 */
public class AuditLogDAO {

    /**
     * Records an immutable audit log entry including IP origin and device information.
     */
    public boolean logAction(AuditLog log) {
        String sql = "INSERT INTO audit_logs (user_id, username, action, entity_type, entity_id, ip_address, device, details) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            if (log.getUserId() != null && log.getUserId() > 0) {
                ps.setInt(1, log.getUserId());
            } else {
                ps.setNull(1, Types.INTEGER);
            }
            ps.setString(2, log.getUsername());
            ps.setString(3, log.getAction());
            ps.setString(4, log.getEntityType());
            if (log.getEntityId() != null && log.getEntityId() > 0) {
                ps.setInt(5, log.getEntityId());
            } else {
                ps.setNull(5, Types.INTEGER);
            }
            ps.setString(6, log.getIpAddress() != null ? log.getIpAddress() : "127.0.0.1");
            ps.setString(7, log.getDevice() != null ? log.getDevice() : "💻 Desktop • Web Browser");
            ps.setString(8, log.getDetails());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Convenience helper to record audit logs with device details.
     */
    public void log(Integer userId, String username, String action, String entityType, Integer entityId, String ipAddress, String device, String details) {
        AuditLog auditLog = new AuditLog(userId, username, action, entityType, entityId, ipAddress, device, details);
        logAction(auditLog);
    }

    /**
     * Convenience helper to record audit logs (backward compatible).
     */
    public void log(Integer userId, String username, String action, String entityType, Integer entityId, String ipAddress, String details) {
        log(userId, username, action, entityType, entityId, ipAddress, "💻 Desktop • Web Browser", details);
    }

    /**
     * Retrieves recent audit logs.
     */
    public List<AuditLog> getRecentLogs(int limit) {
        List<AuditLog> list = new ArrayList<>();
        String sql = "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit <= 0 ? 50 : limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    AuditLog a = new AuditLog();
                    a.setId(rs.getInt("id"));
                    int uid = rs.getInt("user_id");
                    if (!rs.wasNull()) a.setUserId(uid);
                    a.setUsername(rs.getString("username"));
                    a.setAction(rs.getString("action"));
                    a.setEntityType(rs.getString("entity_type"));
                    int eid = rs.getInt("entity_id");
                    if (!rs.wasNull()) a.setEntityId(eid);
                    a.setIpAddress(rs.getString("ip_address"));
                    String dev = rs.getString("device");
                    a.setDevice(dev != null && !dev.trim().isEmpty() ? dev : "💻 Desktop • Web Browser");
                    a.setDetails(rs.getString("details"));
                    a.setTimestamp(rs.getTimestamp("timestamp"));
                    list.add(a);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Retrieves audit logs for a specific entity.
     */
    public List<AuditLog> getLogsByEntity(String entityType, int entityId) {
        List<AuditLog> list = new ArrayList<>();
        String sql = "SELECT * FROM audit_logs WHERE entity_type = ? AND entity_id = ? ORDER BY timestamp DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, entityType);
            ps.setInt(2, entityId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    AuditLog a = new AuditLog();
                    a.setId(rs.getInt("id"));
                    int uid = rs.getInt("user_id");
                    if (!rs.wasNull()) a.setUserId(uid);
                    a.setUsername(rs.getString("username"));
                    a.setAction(rs.getString("action"));
                    a.setEntityType(rs.getString("entity_type"));
                    int eid = rs.getInt("entity_id");
                    if (!rs.wasNull()) a.setEntityId(eid);
                    a.setIpAddress(rs.getString("ip_address"));
                    String dev = rs.getString("device");
                    a.setDevice(dev != null && !dev.trim().isEmpty() ? dev : "💻 Desktop • Web Browser");
                    a.setDetails(rs.getString("details"));
                    a.setTimestamp(rs.getTimestamp("timestamp"));
                    list.add(a);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }
}
