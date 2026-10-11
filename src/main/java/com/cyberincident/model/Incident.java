package com.cyberincident.model;

import java.io.Serializable;
import java.sql.Timestamp;

/**
 * Model representing a Cybersecurity Incident.
 */
public class Incident implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String incidentCode; // e.g. INC-2026-001
    private String title;
    private String description;
    private String category; // Phishing, Ransomware, Malware, DDoS, Data Breach, etc.
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private String status; // REPORTED, UNDER_REVIEW, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    private int reporterId;
    private String reporterName;
    private Integer assignedAnalystId;
    private String assignedAnalystName;
    private String affectedSystem;
    private String impactScope; // Individual, Department, Organization-Wide, External/Client
    private String dataSensitivity; // Public, Internal, Confidential, Highly Sensitive / PII
    private int riskScore; // 0 - 100
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL
    private String recommendedAction;
    private String containmentPlan;
    private String rootCause;
    private String iocIndicators;
    private Timestamp createdAt;
    private Timestamp updatedAt;
    private Timestamp resolvedAt;

    public Incident() {
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getIncidentCode() {
        return incidentCode;
    }

    public void setIncidentCode(String incidentCode) {
        this.incidentCode = incidentCode;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getReporterId() {
        return reporterId;
    }

    public void setReporterId(int reporterId) {
        this.reporterId = reporterId;
    }

    public String getReporterName() {
        return reporterName;
    }

    public void setReporterName(String reporterName) {
        this.reporterName = reporterName;
    }

    public Integer getAssignedAnalystId() {
        return assignedAnalystId;
    }

    public void setAssignedAnalystId(Integer assignedAnalystId) {
        this.assignedAnalystId = assignedAnalystId;
    }

    public String getAssignedAnalystName() {
        return assignedAnalystName;
    }

    public void setAssignedAnalystName(String assignedAnalystName) {
        this.assignedAnalystName = assignedAnalystName;
    }

    public String getAffectedSystem() {
        return affectedSystem;
    }

    public void setAffectedSystem(String affectedSystem) {
        this.affectedSystem = affectedSystem;
    }

    public String getImpactScope() {
        return impactScope;
    }

    public void setImpactScope(String impactScope) {
        this.impactScope = impactScope;
    }

    public String getDataSensitivity() {
        return dataSensitivity;
    }

    public void setDataSensitivity(String dataSensitivity) {
        this.dataSensitivity = dataSensitivity;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }

    public String getContainmentPlan() {
        return containmentPlan;
    }

    public void setContainmentPlan(String containmentPlan) {
        this.containmentPlan = containmentPlan;
    }

    public String getRootCause() {
        return rootCause;
    }

    public void setRootCause(String rootCause) {
        this.rootCause = rootCause;
    }

    public String getIocIndicators() {
        return iocIndicators;
    }

    public void setIocIndicators(String iocIndicators) {
        this.iocIndicators = iocIndicators;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Timestamp updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Timestamp getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(Timestamp resolvedAt) {
        this.resolvedAt = resolvedAt;
    }

    public String getSeverityBadgeClass() {
        if ("CRITICAL".equalsIgnoreCase(severity)) return "badge-critical";
        if ("HIGH".equalsIgnoreCase(severity)) return "badge-high";
        if ("MEDIUM".equalsIgnoreCase(severity)) return "badge-medium";
        return "badge-low";
    }

    public String getStatusBadgeClass() {
        if ("RESOLVED".equalsIgnoreCase(status) || "CLOSED".equalsIgnoreCase(status)) return "badge-resolved";
        if ("CONTAINED".equalsIgnoreCase(status)) return "badge-contained";
        if ("INVESTIGATING".equalsIgnoreCase(status)) return "badge-investigating";
        if ("UNDER_REVIEW".equalsIgnoreCase(status)) return "badge-review";
        return "badge-reported";
    }
}
