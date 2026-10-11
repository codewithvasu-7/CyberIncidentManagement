package com.cyberincident.model;

import java.io.Serializable;
import java.sql.Timestamp;

/**
 * Model representing an Incident chronological update / investigation note.
 */
public class IncidentUpdate implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private int incidentId;
    private int authorId;
    private String authorName;
    private String authorRole;
    private String statusChange;
    private String notes;
    private String actionTaken;
    private Timestamp createdAt;

    public IncidentUpdate() {
    }

    public IncidentUpdate(int incidentId, int authorId, String authorName, String authorRole, String statusChange, String notes, String actionTaken) {
        this.incidentId = incidentId;
        this.authorId = authorId;
        this.authorName = authorName;
        this.authorRole = authorRole;
        this.statusChange = statusChange;
        this.notes = notes;
        this.actionTaken = actionTaken;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(int incidentId) {
        this.incidentId = incidentId;
    }

    public int getAuthorId() {
        return authorId;
    }

    public void setAuthorId(int authorId) {
        this.authorId = authorId;
    }

    public String getAuthorName() {
        return authorName;
    }

    public void setAuthorName(String authorName) {
        this.authorName = authorName;
    }

    public String getAuthorRole() {
        return authorRole;
    }

    public void setAuthorRole(String authorRole) {
        this.authorRole = authorRole;
    }

    public String getStatusChange() {
        return statusChange;
    }

    public void setStatusChange(String statusChange) {
        this.statusChange = statusChange;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public String getActionTaken() {
        return actionTaken;
    }

    public void setActionTaken(String actionTaken) {
        this.actionTaken = actionTaken;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }
}
