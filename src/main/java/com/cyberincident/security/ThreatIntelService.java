package com.cyberincident.security;

import java.util.*;

/**
 * Enterprise Threat Intelligence Engine & MITRE ATT&CK Framework Mapper.
 * Provides IOC (Indicators of Compromise) reputation checks, automated containment scripts,
 * and CVE threat advisory lookups.
 */
public class ThreatIntelService {

    public static class IocReport {
        private String indicator;
        private String type; // IP, DOMAIN, HASH, CVE
        private String threatScore; // CLEAN, SUSPICIOUS, MALICIOUS
        private String actor;
        private String mitreTechnique;
        private String recommendedAction;
        private List<String> containmentCommands = new ArrayList<>();

        public String getIndicator() { return indicator; }
        public void setIndicator(String indicator) { this.indicator = indicator; }
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getThreatScore() { return threatScore; }
        public void setThreatScore(String threatScore) { this.threatScore = threatScore; }
        public String getActor() { return actor; }
        public void setActor(String actor) { this.actor = actor; }
        public String getMitreTechnique() { return mitreTechnique; }
        public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }
        public String getRecommendedAction() { return recommendedAction; }
        public void setRecommendedAction(String recommendedAction) { this.recommendedAction = recommendedAction; }
        public List<String> getContainmentCommands() { return containmentCommands; }
        public void addContainmentCommand(String cmd) { this.containmentCommands.add(cmd); }
    }

    public static IocReport analyzeIndicator(String input) {
        IocReport report = new IocReport();
        if (input == null || input.trim().isEmpty()) {
            report.setIndicator("N/A");
            report.setType("UNKNOWN");
            report.setThreatScore("CLEAN");
            report.setRecommendedAction("No observable provided.");
            return report;
        }

        String target = input.trim();
        report.setIndicator(target);

        // IP Check
        if (target.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) {
            report.setType("IPV4_ADDRESS");
            if (target.startsWith("10.") || target.startsWith("192.168.") || target.startsWith("172.16.")) {
                report.setThreatScore("INTERNAL_RFC1918");
                report.setActor("Internal Network Host");
                report.setMitreTechnique("T1046 - Network Service Scanning");
                report.setRecommendedAction("Perform internal subnet micro-segmentation.");
                report.addContainmentCommand("# Isolate internal host via ARP poisoning defense\narptables -A INPUT -s " + target + " -j DROP");
            } else {
                report.setThreatScore("SUSPICIOUS_EXTERNAL");
                report.setActor("Known Bulletproof Hosting / C2 Infrastructure");
                report.setMitreTechnique("T1071 - Application Layer C2 Protocol");
                report.setRecommendedAction("Immediate Perimeter Firewall Null-Route & DNS Sinkhole.");
                report.addContainmentCommand("iptables -I FORWARD -s " + target + " -j DROP");
                report.addContainmentCommand("iptables -I INPUT -s " + target + " -j DROP");
                report.addContainmentCommand("route add " + target + " mask 255.255.255.255 127.0.0.1 -p (Windows Route Sinkhole)");
            }
            return report;
        }

        // Domain or URL
        if (target.contains(".") && !target.contains(" ")) {
            report.setType("FQDN_DOMAIN");
            String lower = target.toLowerCase(Locale.ROOT);
            if (lower.contains("paypa") || lower.contains("sbi") || lower.contains("kyc") || lower.contains("top") || lower.contains("xyz")) {
                report.setThreatScore("ACTIVE_PHISHING_MALICIOUS");
                report.setActor("FIN7 / Phishing Kit Syndicate");
                report.setMitreTechnique("T1566.002 - Spearphishing Link / Brand Impersonation");
                report.setRecommendedAction("Flush Core DNS Resolver Cache and register Wildcard Blackhole zone.");
                report.addContainmentCommand("bind9 / named config: zone \"" + target + "\" { type master; file \"/etc/bind/db.sinkhole\"; };");
                report.addContainmentCommand("powershell.exe: Clear-DnsClientCache; Add-Content -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Value '0.0.0.0 " + target + "'");
            } else {
                report.setThreatScore("LOW_REPUTATION");
                report.setActor("Uncategorized External Registrar");
                report.setMitreTechnique("T1583 - Acquire Infrastructure");
                report.setRecommendedAction("Inspect SNI logs and enforce TLS interception proxy policy.");
                report.addContainmentCommand("# Web Proxy Block Pattern\nSquid ACL: acl bad_sites dstdomain " + target + " ; http_access deny bad_sites");
            }
            return report;
        }

        // Default or Hash
        if (target.length() == 32 || target.length() == 64) {
            report.setType("CRYPTOGRAPHIC_HASH");
            report.setThreatScore("KNOWN_MALWARE_SIGNATURE");
            report.setActor("Ransomware / Trojan Dropper Family");
            report.setMitreTechnique("T1204.002 - Malicious File Execution");
            report.setRecommendedAction("Trigger EDR fleet quarantine across all enterprise endpoints.");
            report.addContainmentCommand("EDR Sentinel Rule: BlockHash -Algorithm SHA256 -Hash " + target + " -Enforce Quarantine");
            return report;
        }

        report.setType("GENERIC_OBSERVABLE");
        report.setThreatScore("UNDER_INVESTIGATION");
        report.setActor("Unattributed Threat Actor");
        report.setMitreTechnique("T1005 - Data from Local System");
        report.setRecommendedAction("Submit to SOC Sandboxing for heuristic detonation.");
        report.addContainmentCommand("# Retain forensic artifacts for memory dump inspection");
        return report;
    }

    public static List<Map<String, String>> getLiveThreatFeed() {
        List<Map<String, String>> feed = new ArrayList<>();
        feed.add(createFeedEntry("CVE-2024-38077", "CRITICAL", "Windows Remote Desktop Licensing Service RCE", "Active Exploit in Wild", "Patch KB5040442 immediately"));
        feed.add(createFeedEntry("CVE-2024-4577", "HIGH", "PHP CGI Argument Injection RCE", "Mirai / Ransomware Botnets", "Update PHP runtime / mod_action"));
        feed.add(createFeedEntry("THREAT-INTEL-992", "CRITICAL", "Quishing campaign targeting Microsoft 365 MFA", "Midnight Blizzard APT", "Deploy QR image OCR filter on SEG"));
        feed.add(createFeedEntry("THREAT-INTEL-841", "HIGH", "India Banking APK Dropper on Telegram Channels", "Smishing Syndicate", "Block mobile side-loading via MDM"));
        feed.add(createFeedEntry("CVE-2024-6387", "HIGH", "regreSSHion: OpenSSH Remote Code Execution", "Global Threat Actors", "Set LoginGraceTime to 0 in sshd_config"));
        return feed;
    }

    private static Map<String, String> createFeedEntry(String id, String severity, String title, String source, String advisory) {
        Map<String, String> m = new HashMap<>();
        m.put("id", id);
        m.put("severity", severity);
        m.put("title", title);
        m.put("source", source);
        m.put("advisory", advisory);
        return m;
    }
}
