package com.cyberincident.dao;

import com.cyberincident.model.Incident;
import com.cyberincident.model.IncidentUpdate;

import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Data Access Object for Incident records and chronological updates.
 */
public class IncidentDAO {

    /**
     * Inserts a new Incident.
     */
    public boolean createIncident(Incident incident) {
        String sql = "INSERT INTO incidents (incident_code, title, description, category, severity, status, " +
                     "reporter_id, reporter_name, assigned_analyst_id, assigned_analyst_name, affected_system, " +
                     "impact_scope, data_sensitivity, risk_score, risk_level, recommended_action, containment_plan, " +
                     "root_cause, ioc_indicators) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, incident.getIncidentCode());
            ps.setString(2, incident.getTitle());
            ps.setString(3, incident.getDescription());
            ps.setString(4, incident.getCategory());
            ps.setString(5, incident.getSeverity());
            ps.setString(6, incident.getStatus());
            ps.setInt(7, incident.getReporterId());
            ps.setString(8, incident.getReporterName());

            if (incident.getAssignedAnalystId() != null && incident.getAssignedAnalystId() > 0) {
                ps.setInt(9, incident.getAssignedAnalystId());
                ps.setString(10, incident.getAssignedAnalystName());
            } else {
                ps.setNull(9, Types.INTEGER);
                ps.setNull(10, Types.VARCHAR);
            }

            ps.setString(11, incident.getAffectedSystem());
            ps.setString(12, incident.getImpactScope());
            ps.setString(13, incident.getDataSensitivity());
            ps.setInt(14, incident.getRiskScore());
            ps.setString(15, incident.getRiskLevel());
            ps.setString(16, incident.getRecommendedAction());
            ps.setString(17, incident.getContainmentPlan());
            ps.setString(18, incident.getRootCause());
            ps.setString(19, incident.getIocIndicators());

            int affectedRows = ps.executeUpdate();
            if (affectedRows > 0) {
                try (ResultSet rs = ps.getGeneratedKeys()) {
                    if (rs.next()) {
                        incident.setId(rs.getInt(1));
                    }
                }
                return true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Generates a unique incident code (e.g. INC-2026-006).
     */
    public synchronized String generateNextIncidentCode() {
        String year = new SimpleDateFormat("yyyy").format(new Date());
        String prefix = "INC-" + year + "-";
        String sql = "SELECT COALESCE(MAX(id), 0) + 1 FROM incidents";
        int count = 1;
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                count = rs.getInt(1);
            }
        } catch (SQLException e) {
            count = (int) (System.currentTimeMillis() % 1000);
        }
        return String.format("%s%03d", prefix, count);
    }

    /**
     * Retrieves an incident by ID.
     */
    public Incident getIncidentById(int id) {
        String sql = "SELECT * FROM incidents WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToIncident(rs);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Retrieves an incident by code.
     */
    public Incident getIncidentByCode(String code) {
        String sql = "SELECT * FROM incidents WHERE incident_code = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, code);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapResultSetToIncident(rs);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Lists all incidents ordered by creation date descending.
     */
    public List<Incident> getAllIncidents() {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                list.add(mapResultSetToIncident(rs));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Retrieves incidents reported by a specific user.
     */
    public List<Incident> getIncidentsByReporter(int reporterId) {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents WHERE reporter_id = ? ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, reporterId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToIncident(rs));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Retrieves incidents assigned to a specific analyst.
     */
    public List<Incident> getIncidentsByAnalyst(int analystId) {
        List<Incident> list = new ArrayList<>();
        String sql = "SELECT * FROM incidents WHERE assigned_analyst_id = ? ORDER BY created_at DESC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, analystId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToIncident(rs));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Filters incidents by status, severity, category, or search text.
     */
    public List<Incident> filterIncidents(String status, String severity, String category, String query) {
        List<Incident> list = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT * FROM incidents WHERE 1=1 ");
        List<Object> params = new ArrayList<>();

        if (status != null && !status.trim().isEmpty() && !"ALL".equalsIgnoreCase(status)) {
            sql.append("AND status = ? ");
            params.add(status.trim());
        }
        if (severity != null && !severity.trim().isEmpty() && !"ALL".equalsIgnoreCase(severity)) {
            sql.append("AND severity = ? ");
            params.add(severity.trim());
        }
        if (category != null && !category.trim().isEmpty() && !"ALL".equalsIgnoreCase(category)) {
            sql.append("AND category = ? ");
            params.add(category.trim());
        }
        if (query != null && !query.trim().isEmpty()) {
            sql.append("AND (title LIKE ? OR incident_code LIKE ? OR affected_system LIKE ? OR description LIKE ?) ");
            String q = "%" + query.trim() + "%";
            params.add(q);
            params.add(q);
            params.add(q);
            params.add(q);
        }
        sql.append("ORDER BY created_at DESC");

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToIncident(rs));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Updates incident status, severity, and sets resolved_at timestamp when resolved.
     */
    public boolean updateStatusAndSeverity(int incidentId, String status, String severity) {
        boolean isResolved = "RESOLVED".equalsIgnoreCase(status) || "CLOSED".equalsIgnoreCase(status);
        String sql = isResolved
                ? "UPDATE incidents SET status = ?, severity = ?, resolved_at = IFNULL(resolved_at, NOW()) WHERE id = ?"
                : "UPDATE incidents SET status = ?, severity = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, severity);
            ps.setInt(3, incidentId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Reassigns an analyst to the incident.
     */
    public boolean assignAnalyst(int incidentId, Integer analystId, String analystName) {
        String sql = "UPDATE incidents SET assigned_analyst_id = ?, assigned_analyst_name = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            if (analystId != null && analystId > 0) {
                ps.setInt(1, analystId);
                ps.setString(2, analystName);
            } else {
                ps.setNull(1, Types.INTEGER);
                ps.setNull(2, Types.VARCHAR);
            }
            ps.setInt(3, incidentId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Updates investigation findings, containment plan, root cause, and IOC indicators.
     */
    public boolean updateInvestigationDetails(int incidentId, String rootCause, String containmentPlan, String iocIndicators) {
        String sql = "UPDATE incidents SET root_cause = ?, containment_plan = ?, ioc_indicators = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, rootCause);
            ps.setString(2, containmentPlan);
            ps.setString(3, iocIndicators);
            ps.setInt(4, incidentId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Adds an entry to incident chronological updates.
     */
    public boolean addIncidentUpdate(IncidentUpdate update) {
        String sql = "INSERT INTO incident_updates (incident_id, author_id, author_name, author_role, status_change, notes, action_taken) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, update.getIncidentId());
            ps.setInt(2, update.getAuthorId());
            ps.setString(3, update.getAuthorName());
            ps.setString(4, update.getAuthorRole());
            ps.setString(5, update.getStatusChange());
            ps.setString(6, update.getNotes());
            ps.setString(7, update.getActionTaken());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Gets updates / timeline entries for an incident.
     */
    public List<IncidentUpdate> getIncidentUpdates(int incidentId) {
        List<IncidentUpdate> list = new ArrayList<>();
        String sql = "SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, incidentId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    IncidentUpdate u = new IncidentUpdate();
                    u.setId(rs.getInt("id"));
                    u.setIncidentId(rs.getInt("incident_id"));
                    u.setAuthorId(rs.getInt("author_id"));
                    u.setAuthorName(rs.getString("author_name"));
                    u.setAuthorRole(rs.getString("author_role"));
                    u.setStatusChange(rs.getString("status_change"));
                    u.setNotes(rs.getString("notes"));
                    u.setActionTaken(rs.getString("action_taken"));
                    u.setCreatedAt(rs.getTimestamp("created_at"));
                    list.add(u);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * Deletes an incident (Admin only).
     */
    public boolean deleteIncident(int id) {
        String sql = "DELETE FROM incidents WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, id);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private Incident mapResultSetToIncident(ResultSet rs) throws SQLException {
        Incident inc = new Incident();
        inc.setId(rs.getInt("id"));
        inc.setIncidentCode(rs.getString("incident_code"));
        inc.setTitle(rs.getString("title"));
        inc.setDescription(rs.getString("description"));
        inc.setCategory(rs.getString("category"));
        inc.setSeverity(rs.getString("severity"));
        inc.setStatus(rs.getString("status"));
        inc.setReporterId(rs.getInt("reporter_id"));
        inc.setReporterName(rs.getString("reporter_name"));

        int analystId = rs.getInt("assigned_analyst_id");
        if (!rs.wasNull()) {
            inc.setAssignedAnalystId(analystId);
        }
        inc.setAssignedAnalystName(rs.getString("assigned_analyst_name"));
        inc.setAffectedSystem(rs.getString("affected_system"));
        inc.setImpactScope(rs.getString("impact_scope"));
        inc.setDataSensitivity(rs.getString("data_sensitivity"));
        inc.setRiskScore(rs.getInt("risk_score"));
        inc.setRiskLevel(rs.getString("risk_level"));
        inc.setRecommendedAction(rs.getString("recommended_action"));
        inc.setContainmentPlan(rs.getString("containment_plan"));
        inc.setRootCause(rs.getString("root_cause"));
        inc.setIocIndicators(rs.getString("ioc_indicators"));
        inc.setCreatedAt(rs.getTimestamp("created_at"));
        inc.setUpdatedAt(rs.getTimestamp("updated_at"));
        inc.setResolvedAt(rs.getTimestamp("resolved_at"));
        return inc;
    }
}
