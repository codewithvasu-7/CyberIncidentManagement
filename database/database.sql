-- ====================================================================
-- Cybersecurity Incident Reporting & Management System (CIRMS)
-- Database: cyber_incident_db
-- ====================================================================

DROP DATABASE IF EXISTS cyber_incident_db;
CREATE DATABASE cyber_incident_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyber_incident_db;

-- --------------------------------------------------------------------
-- 1. Table: users
-- Stores system users across 3 roles: USER, ANALYST, ADMIN
-- --------------------------------------------------------------------
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    role ENUM('USER', 'ANALYST', 'ADMIN') NOT NULL DEFAULT 'USER',
    status ENUM('ACTIVE', 'INACTIVE', 'SUSPENDED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB;

-- --------------------------------------------------------------------
-- 2. Table: incidents
-- Core incident registry with automated risk triage and SOC tracking
-- --------------------------------------------------------------------
CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_code VARCHAR(30) NOT NULL UNIQUE,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    status ENUM('REPORTED', 'UNDER_REVIEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED') NOT NULL DEFAULT 'REPORTED',
    reporter_id INT NOT NULL,
    reporter_name VARCHAR(100) NOT NULL,
    assigned_analyst_id INT NULL DEFAULT NULL,
    assigned_analyst_name VARCHAR(100) NULL DEFAULT NULL,
    affected_system VARCHAR(150) NOT NULL,
    impact_scope VARCHAR(50) NOT NULL DEFAULT 'Department',
    data_sensitivity VARCHAR(50) NOT NULL DEFAULT 'Internal',
    risk_score INT NOT NULL DEFAULT 0,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    recommended_action TEXT NULL,
    containment_plan TEXT NULL,
    root_cause TEXT NULL,
    ioc_indicators TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL DEFAULT NULL,
    CONSTRAINT fk_incident_reporter FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_analyst FOREIGN KEY (assigned_analyst_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- --------------------------------------------------------------------
-- 3. Table: incident_updates
-- Incident chronology, investigative logs, comments and audit timeline
-- --------------------------------------------------------------------
CREATE TABLE incident_updates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    author_id INT NOT NULL,
    author_name VARCHAR(100) NOT NULL,
    author_role VARCHAR(20) NOT NULL,
    status_change VARCHAR(50) NULL DEFAULT NULL,
    notes TEXT NOT NULL,
    action_taken VARCHAR(255) NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_update_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_update_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- --------------------------------------------------------------------
-- 4. Table: audit_logs
-- Comprehensive immutable security audit trail
-- --------------------------------------------------------------------
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL DEFAULT NULL,
    username VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id INT NULL DEFAULT NULL,
    ip_address VARCHAR(45) NULL DEFAULT '127.0.0.1',
    device VARCHAR(150) NULL DEFAULT 'Desktop / Web Browser',
    details TEXT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB;

-- --------------------------------------------------------------------
-- SEED DATA
-- Default Passwords:
-- Admin:    admin / Admin@123
-- Analyst:  analyst_raj / Analyst@123
-- User:     john_doe / User@123
-- Salt:     b8d9609a34fd695d (Hex representation)
-- SHA-256(password + salt)
-- Admin@123:    fb4ad6c1aef54427bf56f37f20b1e3fb7bcc78440d5612d49191f8f577b8d753
-- Analyst@123:  2e923b4fb78aa36f037a5e7c8df6efe86fe88c40c669565ad4b839fa64e71e93
-- User@123:     c583fdb765ceda299e7ff16772c64fd36d0c6f91e6fdd21dffe33831bc31c407
-- --------------------------------------------------------------------

INSERT INTO users (id, username, email, password_hash, salt, full_name, department, role, status, created_at) VALUES
(1, 'admin', 'admin@soc.corp', 'fb4ad6c1aef54427bf56f37f20b1e3fb7bcc78440d5612d49191f8f577b8d753', 'b8d9609a34fd695d', 'Chief Security Officer', 'Information Security', 'ADMIN', 'ACTIVE', NOW()),
(2, 'analyst_raj', 'raj.sharma@soc.corp', '2e923b4fb78aa36f037a5e7c8df6efe86fe88c40c669565ad4b839fa64e71e93', 'b8d9609a34fd695d', 'Raj Sharma (Tier-2 SOC)', 'SOC Operations', 'ANALYST', 'ACTIVE', NOW()),
(3, 'analyst_priya', 'priya.singh@soc.corp', '2e923b4fb78aa36f037a5e7c8df6efe86fe88c40c669565ad4b839fa64e71e93', 'b8d9609a34fd695d', 'Priya Singh (Incident Responder)', 'SOC Operations', 'ANALYST', 'ACTIVE', NOW()),
(4, 'john_doe', 'john.doe@enterprise.corp', 'c583fdb765ceda299e7ff16772c64fd36d0c6f91e6fdd21dffe33831bc31c407', 'b8d9609a34fd695d', 'John Doe', 'Finance & Accounting', 'USER', 'ACTIVE', NOW()),
(5, 'alice_smith', 'alice.smith@enterprise.corp', 'c583fdb765ceda299e7ff16772c64fd36d0c6f91e6fdd21dffe33831bc31c407', 'b8d9609a34fd695d', 'Alice Smith', 'Human Resources', 'USER', 'ACTIVE', NOW());

-- Seed Initial Realistic Cybersecurity Incidents
INSERT INTO incidents (id, incident_code, title, description, category, severity, status, reporter_id, reporter_name, assigned_analyst_id, assigned_analyst_name, affected_system, impact_scope, data_sensitivity, risk_score, risk_level, recommended_action, containment_plan, root_cause, ioc_indicators, created_at, updated_at, resolved_at) VALUES
(1, 'INC-2026-001', 'Targeted Spear-Phishing Campaign on Finance Dept', 
'Multiple finance employees received fraudulent invoices containing macro-enabled Excel attachments spoofing executive vendors.', 
'Phishing', 'HIGH', 'CONTAINED', 4, 'John Doe', 2, 'Raj Sharma (Tier-2 SOC)', 
'Finance Exchange Mailbox & Workstations', 'Department', 'Confidential', 
78, 'HIGH', 
'Block sender domain, purge malicious emails from all mailboxes, reset potentially compromised credentials.', 
'Mail gateway rule enacted. Blocked external IP 185.220.101.44. Workstation isolations verified.', 
'Compromised third-party supplier email account used for spoofed invoice delivery.', 
'IP: 185.220.101.44 | Domain: evil-invoice-auth.cc | MD5: 44d88612fea8a8f36de82e1278abb02f', 
DATE_SUB(NOW(), INTERVAL 2 DAY), DATE_SUB(NOW(), INTERVAL 4 HOUR), NULL),

(2, 'INC-2026-002', 'Ransomware Canary Alert on NAS Storage Cluster', 
'High volume of rapid file extension renames to .locked observed on shared network volume /mnt/storage/corp.', 
'Ransomware', 'CRITICAL', 'INVESTIGATING', 1, 'Chief Security Officer', 2, 'Raj Sharma (Tier-2 SOC)', 
'Core NAS Storage & Active Directory', 'Organization-Wide', 'Highly Sensitive / PII', 
96, 'CRITICAL', 
'Immediately sever SMB share connections, isolate origin IP from VLAN, verify offline shadow backups.', 
'Disconnected switch port 24 on core switch. Suspended mapped network drives enterprise-wide.', 
'Unpatched SMB vulnerability on legacy staging server leading to lateral movement.', 
'Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | C2: 91.240.118.17:4444', 
DATE_SUB(NOW(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 1 HOUR), NULL),

(3, 'INC-2026-003', 'Abnormal Outbound Data Transfer to Unknown Cloud Bucket', 
'DLP sensor triggered alert for 45GB compressed archive egressed outside business hours from development cluster.', 
'Data Breach', 'CRITICAL', 'UNDER_REVIEW', 1, 'Chief Security Officer', 3, 'Priya Singh (Incident Responder)', 
'Production Database & API Gateway', 'Organization-Wide', 'Highly Sensitive / PII', 
88, 'CRITICAL', 
'Revoke exposed AWS/S3 access keys, freeze affected API tokens, initiate forensic memory dump.', 
'API keys rotated. Egress firewall policy tightened to whitelist only.', 
'Under review - probable leaked developer credentials via public GitHub repository.', 
'Destination: storage-sync-cloud-cdn.xyz | Source IP: 10.0.4.112', 
DATE_SUB(NOW(), INTERVAL 6 HOUR), NOW(), NULL),

(4, 'INC-2026-004', 'DDoS Volumetric UDP Flood on Customer Portal', 
'Public customer gateway experienced 120 Gbps UDP flood resulting in intermittent 504 Gateway Timeouts.', 
'DDoS', 'MEDIUM', 'RESOLVED', 4, 'John Doe', 2, 'Raj Sharma (Tier-2 SOC)', 
'Public Web Application Gateway', 'Organization-Wide', 'Public', 
55, 'MEDIUM', 
'Engage Cloudflare/Akamai scrubbing centers, drop non-SYN packets at edge routers.', 
'BGP route announced through DDoS scrubbing center; attack traffic mitigated.', 
'Botnet NTP amplification attack targeted towards DNS/Web frontend.', 
'Amplification Vectors: NTP Monlist, UDP Port 123 reflections', 
DATE_SUB(NOW(), INTERVAL 3 DAY), DATE_SUB(NOW(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 1 DAY)),

(5, 'INC-2026-005', 'Repeated Failed SSH Brute Force Attempts on Bastion Host', 
'Over 14,000 SSH authentication failures detected within 15 minutes targeting root and admin accounts.', 
'Unauthorized Access', 'LOW', 'RESOLVED', 5, 'Alice Smith', 3, 'Priya Singh (Incident Responder)', 
'Linux Bastion Host (192.168.1.10)', 'Internal', 'Internal', 
34, 'LOW', 
'Enforce fail2ban jail, disable password authentication in favor of ed25519 keys, rotate port.', 
'Fail2ban dropped offending subnets. Key-based authentication confirmed.', 
'Internet-facing port 22 exposed to automated crawler dictionary attacks.', 
'Offending IP range: 45.154.255.0/24', 
DATE_SUB(NOW(), INTERVAL 5 DAY), DATE_SUB(NOW(), INTERVAL 4 DAY), DATE_SUB(NOW(), INTERVAL 4 DAY));

-- Seed Timeline Updates
INSERT INTO incident_updates (incident_id, author_id, author_name, author_role, status_change, notes, action_taken, created_at) VALUES
(1, 4, 'John Doe', 'USER', 'REPORTED', 'Found suspicious invoice from vendor asking to enable VBA macros.', 'Forwarded email to security desk.', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(1, 2, 'Raj Sharma (Tier-2 SOC)', 'ANALYST', 'UNDER_REVIEW', 'Analyzed attachment in sandbox. Confirmed Emotet payload downloader.', 'Extracted IOCs and verified hashes.', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(1, 2, 'Raj Sharma (Tier-2 SOC)', 'ANALYST', 'CONTAINED', 'Domain blacklisted in Cisco Umbrella and Fortinet firewall.', 'Host isolated from Active Directory.', DATE_SUB(NOW(), INTERVAL 4 HOUR)),
(2, 1, 'Chief Security Officer', 'ADMIN', 'REPORTED', 'Canary honeypot file triggered ransomware trap.', 'Emergency alarm raised.', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(2, 2, 'Raj Sharma (Tier-2 SOC)', 'ANALYST', 'INVESTIGATING', 'Lateral movement identified via compromised admin service account.', 'Password reset triggered for all service accounts.', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(4, 2, 'Raj Sharma (Tier-2 SOC)', 'ANALYST', 'RESOLVED', 'Upstream ISP applied scrubbing filter. Latency back to normal 25ms.', 'Closed incident report.', DATE_SUB(NOW(), INTERVAL 1 DAY));

-- Seed Audit Logs
INSERT INTO audit_logs (user_id, username, action, entity_type, entity_id, ip_address, details, timestamp) VALUES
(1, 'admin', 'SYSTEM_INITIALIZATION', 'SYSTEM', 0, '127.0.0.1', 'CIRMS Database and Security Rules Initialized.', DATE_SUB(NOW(), INTERVAL 7 DAY)),
(4, 'john_doe', 'USER_LOGIN', 'USER', 4, '192.168.1.105', 'User login successful.', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(4, 'john_doe', 'INCIDENT_REPORTED', 'INCIDENT', 1, '192.168.1.105', 'Incident INC-2026-001 reported by John Doe.', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(2, 'analyst_raj', 'INCIDENT_TRIAGED', 'INCIDENT', 1, '10.0.2.15', 'Risk score calculated: 78 (HIGH). Playbook attached.', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(2, 'analyst_raj', 'INCIDENT_STATUS_UPDATE', 'INCIDENT', 1, '10.0.2.15', 'Status updated to CONTAINED.', DATE_SUB(NOW(), INTERVAL 4 HOUR));
