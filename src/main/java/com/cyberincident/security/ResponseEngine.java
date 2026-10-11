package com.cyberincident.security;

import java.util.Locale;

/**
 * Automated Incident Response Engine based on NIST SP 800-61 / SANS CIRT standards.
 * Dynamically synthesizes containment playbooks, immediate triage directives,
 * and forensic acquisition guidance based on incident category and risk assessment.
 */
public class ResponseEngine {

    public static class ResponsePlan {
        private final String recommendedAction;
        private final String containmentPlan;

        public ResponsePlan(String recommendedAction, String containmentPlan) {
            this.recommendedAction = recommendedAction;
            this.containmentPlan = containmentPlan;
        }

        public String getRecommendedAction() {
            return recommendedAction;
        }

        public String getContainmentPlan() {
            return containmentPlan;
        }
    }

    /**
     * Synthesizes automated recommended action and containment plan.
     */
    public static ResponsePlan generatePlaybook(String category, String riskLevel, String affectedSystem) {
        String cat = (category != null) ? category.trim().toUpperCase(Locale.ROOT) : "OTHER";
        String risk = (riskLevel != null) ? riskLevel.trim().toUpperCase(Locale.ROOT) : "MEDIUM";
        String asset = (affectedSystem != null) ? affectedSystem.trim() : "Affected Target";

        String actions;
        String containment;

        switch (cat) {
            case "PHISHING":
                actions = "1. Block sending sender IP and malicious domain at DNS & Mail Gateway.\n" +
                          "2. Purge matching phishing messages across all tenant mailboxes using PowerShell/EAC.\n" +
                          "3. Force password reset and revoke active OAuth session tokens for affected users.\n" +
                          "4. Verify whether recipient clicked link or submitted MFA credentials.";
                containment = "Quarantine suspicious emails enterprise-wide. Isolate client workstation '" + asset + "' pending AV full-scan and browser cache forensics.";
                break;

            case "RANSOMWARE":
                actions = "1. [CRITICAL EMERGENCY] Immediately sever physical Ethernet and disable Wi-Fi/Bluetooth on '" + asset + "'.\n" +
                          "2. Block SMB Port 445 and RPC Port 135 across internal switches to halt lateral traversal.\n" +
                          "3. Preserve memory dump (RAM) prior to shutdown for volatile key extraction.\n" +
                          "4. Notify CISO, Legal, and cyber insurance providers within statutory notification window.\n" +
                          "5. Verify immutable air-gapped / shadow copy backups integrity before restore.";
                containment = "Execute network segmentation isolation on VLAN. Revoke enterprise admin credentials and freeze domain controller write operations.";
                break;

            case "DATA BREACH":
            case "DATA_BREACH":
                actions = "1. Immediately rotate exposed API tokens, database passwords, and cloud IAM credentials.\n" +
                          "2. Inspect SIEM egress logs for destination IP addresses, byte volume, and transfer protocol.\n" +
                          "3. Classify compromised data scope (PII, financial, intellectual property).\n" +
                          "4. Freeze audit log retention policies to prevent tamper or log rotation.";
                containment = "Sever outbound firewall connections to suspicious IP/port endpoints. Revoke compromised user / service account permissions on '" + asset + "'.";
                break;

            case "DDOS":
                actions = "1. Engage upstream ISP / CDN scrubbing centers (Cloudflare / AWS Shield / Akamai).\n" +
                          "2. Implement rate limiting on ingress load balancer and enforce geo-blocking / ASN filtering.\n" +
                          "3. Enable aggressive SYN cookies, drop fragmented UDP / ICMP floods at border edge routers.\n" +
                          "4. Monitor backend CPU and connection pool exhaustion on '" + asset + "'.";
                containment = "Shift ingress DNS traffic through CDN reverse proxy. Deploy WAF rate-limiting rule (max 100 req/min per IP).";
                break;

            case "MALWARE":
                actions = "1. Disconnect endpoint '" + asset + "' from corporate network.\n" +
                          "2. Run live EDR process inspection to identify malicious parent-child execution chains.\n" +
                          "3. Calculate cryptographic hash (SHA-256) of executable; cross-reference on VirusTotal / MISP.\n" +
                          "4. Check for persistence hooks (scheduled tasks, registry Run keys, systemd daemons).";
                containment = "Quarantine infected binaries via EDR agent. Terminate offending process PIDs and block external C2 command IPs.";
                break;

            case "UNAUTHORIZED ACCESS":
            case "UNAUTHORIZED_ACCESS":
                actions = "1. Immediately terminate active user sessions and force MFA re-registration.\n" +
                          "2. Correlate VPN / SSH / Active Directory event IDs (4624, 4625) for origin geolocation.\n" +
                          "3. Audit recent privilege escalation attempts, sudo log entries, and newly created local accounts.\n" +
                          "4. Rotate all service credentials accessible from '" + asset + "'.";
                containment = "Null-route attacker IP at perimeter firewall. Restrict administrative port access to strict bastion jumpbox whitelist.";
                break;

            case "INSIDER THREAT":
            case "INSIDER_THREAT":
                actions = "1. Place hold on employee user account, email forwarding rules, and cloud drives.\n" +
                          "2. Review USB device mount logs, DLP transfers, and after-hours remote access sessions.\n" +
                          "3. Coordinate with Human Resources and Legal before confronting subject.\n" +
                          "4. Secure physical access badge records and security camera footage.";
                containment = "Suspend Active Directory account and revoke building badge access. Mirror disk image for chain-of-custody compliance.";
                break;

            default:
                actions = "1. Conduct initial triage interview with reporter to gather timeline and observables.\n" +
                          "2. Preserve system logs, packet captures, and screenshots of anomalies.\n" +
                          "3. Perform vulnerability scan on '" + asset + "' to determine exposure window.\n" +
                          "4. Escalate to Lead Security Analyst if severity upgrades to HIGH or CRITICAL.";
                containment = "Apply restrictive firewall security group around '" + asset + "' and monitor anomalous telemetry.";
                break;
        }

        if ("CRITICAL".equals(risk)) {
            actions = "[PRIORITY 1 - SOC SEVERITY CRITICAL]\n" + actions + 
                      "\n5. Convene Emergency Incident Response Team (IRT) War Room within 15 minutes.";
        }

        return new ResponsePlan(actions, containment);
    }
}
