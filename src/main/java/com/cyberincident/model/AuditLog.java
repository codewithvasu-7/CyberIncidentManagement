package com.cyberincident.model;

import java.io.Serializable;
import java.sql.Timestamp;

/**
 * Model representing an immutable Security Audit Log entry.
 */
public class AuditLog implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private Integer userId;
    private String username;
    private String action;
    private String entityType;
    private Integer entityId;
    private String ipAddress;
    private String device;
    private String details;
    private Timestamp timestamp;

    public AuditLog() {
    }

    public AuditLog(Integer userId, String username, String action, String entityType, Integer entityId, String ipAddress, String details) {
        this(userId, username, action, entityType, entityId, ipAddress, "💻 Desktop • Web Browser", details);
    }

    public AuditLog(Integer userId, String username, String action, String entityType, Integer entityId, String ipAddress, String device, String details) {
        this.userId = userId;
        this.username = username;
        this.action = action;
        this.entityType = entityType;
        this.entityId = entityId;
        this.ipAddress = ipAddress;
        this.device = device;
        this.details = details;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getEntityType() {
        return entityType;
    }

    public void setEntityType(String entityType) {
        this.entityType = entityType;
    }

    public Integer getEntityId() {
        return entityId;
    }

    public void setEntityId(Integer entityId) {
        this.entityId = entityId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
}
