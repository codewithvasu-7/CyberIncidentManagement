package com.cyberincident.security;

import com.cyberincident.model.Incident;
import com.cyberincident.model.UrlScanResult;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Automated Cyber Incident Forensic Investigation Engine.
 * 
 * Specializes in diagnosing malicious link detonations, accidental link clicks,
 * credential harvesting, session token exfiltration, and drive-by compromises.
 * Synthesizes:
 *  1. "What Happened To You?" (Human-readable forensic root cause).
 *  2. "What Data Was Potentially Compromised?" (Telemetry, Cookies, Credentials, Autofill).
 *  3. "Immediate Step-by-Step Remediation Plan" (Prioritized emergency response).
 *  4. SOC Containment & IOC extraction directives.
 */
public class IncidentForensicEngine {

    // Regex to locate URLs, hostnames or raw IPs inside incident descriptions and IOC fields
    private static final Pattern URL_REGEX = Pattern.compile(
            "(https?://[a-zA-Z0-9+&@#/%?=~_|!:,.;\\-]+[a-zA-Z0-9+&@#/%=~_|])|" +
            "(www\\.[a-zA-Z0-9+&@#/%?=~_|!:,.;\\-]+[a-zA-Z0-9+&@#/%=~_|])|" +
            "([a-zA-Z0-9-]+\\.(?:xyz|top|tk|ml|ga|cf|gq|buzz|club|work|click|ru|cc|to|vip|icu|monster|quest|live|fit|rest|online|site|bar|com|net|org|io|dev|app|biz)/[^\\s]*)|" +
            "(\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]{1,5})?(?:/[^\\s]*)?\\b)",
            Pattern.CASE_INSENSITIVE
    );

    public static class ForensicResult {
        private boolean linkAnalyzed;
        private String targetUrl;
        private String targetDomain;
        private String attackVector;
        private String whatHappened;
        private List<String> compromisedDataItems = new ArrayList<>();
        private List<String> emergencyActions = new ArrayList<>();
        private String containmentStrategy;
        private int adjustedRiskScore;
        private String adjustedRiskLevel;
        private String adjustedSeverity;
        private UrlScanResult urlScanResult;

        public boolean isLinkAnalyzed() { return linkAnalyzed; }
        public void setLinkAnalyzed(boolean linkAnalyzed) { this.linkAnalyzed = linkAnalyzed; }

        public String getTargetUrl() { return targetUrl; }
        public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

        public String getTargetDomain() { return targetDomain; }
        public void setTargetDomain(String targetDomain) { this.targetDomain = targetDomain; }

        public String getAttackVector() { return attackVector; }
        public void setAttackVector(String attackVector) { this.attackVector = attackVector; }

        public String getWhatHappened() { return whatHappened; }
        public void setWhatHappened(String whatHappened) { this.whatHappened = whatHappened; }

        public List<String> getCompromisedDataItems() { return compromisedDataItems; }
        public void setCompromisedDataItems(List<String> items) { this.compromisedDataItems = items; }

        public List<String> getEmergencyActions() { return emergencyActions; }
        public void setEmergencyActions(List<String> actions) { this.emergencyActions = actions; }

        public String getContainmentStrategy() { return containmentStrategy; }
        public void setContainmentStrategy(String strategy) { this.containmentStrategy = strategy; }

        public int getAdjustedRiskScore() { return adjustedRiskScore; }
        public void setAdjustedRiskScore(int score) { this.adjustedRiskScore = score; }

        public String getAdjustedRiskLevel() { return adjustedRiskLevel; }
        public void setAdjustedRiskLevel(String level) { this.adjustedRiskLevel = level; }

        public String getAdjustedSeverity() { return adjustedSeverity; }
        public void setAdjustedSeverity(String severity) { this.adjustedSeverity = severity; }

        public UrlScanResult getUrlScanResult() { return urlScanResult; }
        public void setUrlScanResult(UrlScanResult result) { this.urlScanResult = result; }
    }

    /**
     * Conducts deep forensic triage on an incident submission and enriches the Incident record.
     */
    public static ForensicResult diagnose(Incident incident) {
        ForensicResult result = new ForensicResult();

        String combinedText = (incident.getTitle() != null ? incident.getTitle() : "") + " " +
                              (incident.getDescription() != null ? incident.getDescription() : "") + " " +
                              (incident.getIocIndicators() != null ? incident.getIocIndicators() : "");

        String extractedUrl = extractUrl(combinedText);
        boolean isQr = combinedText.toLowerCase(Locale.ROOT).contains("qr") ||
                       combinedText.toLowerCase(Locale.ROOT).contains("quishing");

        UrlScanResult scanResult = null;
        if (extractedUrl != null && !extractedUrl.trim().isEmpty()) {
            result.setLinkAnalyzed(true);
            result.setTargetUrl(extractedUrl);
            scanResult = UrlSecurityScanner.scanUrl(extractedUrl, isQr);
            result.setUrlScanResult(scanResult);
            result.setTargetDomain(scanResult.getDomain());
        }

        // Analyze user behavioral clues in the incident description
        String textLower = combinedText.toLowerCase(Locale.ROOT);
        boolean enteredCredentials = textLower.contains("password") || textLower.contains("login") ||
                                      textLower.contains("entered") || textLower.contains("credential") ||
                                      textLower.contains("otp") || textLower.contains("pin") || textLower.contains("bhara");
        boolean financialInvolved = textLower.contains("bank") || textLower.contains("card") ||
                                    textLower.contains("payment") || textLower.contains("upi") ||
                                    textLower.contains("wallet") || textLower.contains("money") ||
                                    textLower.contains("paisa") || textLower.contains("khata");
        boolean downloadedFile = textLower.contains("download") || textLower.contains(".exe") ||
                                 textLower.contains(".apk") || textLower.contains("install") ||
                                 textLower.contains("file");
        boolean openedLink = textLower.contains("open") || textLower.contains("click") ||
                             textLower.contains("link") || textLower.contains("url") ||
                             textLower.contains("fetch") || textLower.contains("galti");

        // Determine Attack Vector
        String vector;
        if (scanResult != null && scanResult.isMalware()) {
            vector = "Drive-By Malware / Payload Dropper Link";
        } else if (scanResult != null && scanResult.isQuishing()) {
            vector = "Quishing (Malicious QR Code Redirection)";
        } else if (enteredCredentials) {
            vector = "Credential Harvesting & Authentication Impersonation Phish";
        } else if (openedLink && (scanResult != null && scanResult.getRiskScore() >= 40)) {
            vector = "Malicious Link Click & Client Data Exfiltration / Token Snooping";
        } else if (financialInvolved) {
            vector = "Financial Deception & Payment Phishing Scheme";
        } else if (scanResult != null && "PHISHING".equals(scanResult.getThreatLevel())) {
            vector = "Sophisticated Social Engineering Phishing Ingress";
        } else {
            vector = "Unauthorized Web Ingress & Client Telemetry Exposure";
        }
        result.setAttackVector(vector);

        // Synthesize "What Happened To You?"
        StringBuilder whatHappened = new StringBuilder();
        whatHappened.append("### 🔍 Forensic Investigation & Incident Breakdown\n\n");
        whatHappened.append("**Summary Analysis:**\n");
        if (openedLink) {
            whatHappened.append("You encountered a deceptive link lure and opened it. When a user clicks an adversarial link, the browser automatically connects to the attacker's web infrastructure.\n\n");
        } else {
            whatHappened.append("A security query was registered regarding suspicious activity and potential data compromise.\n\n");
        }

        whatHappened.append("**Exact Attack Mechanism:**\n");
        if (scanResult != null) {
            whatHappened.append("1. **Target Detonation:** CIRMS analyzed destination host `").append(scanResult.getDomain()).append("`.\n");
            if (scanResult.getThreatIndicators() != null && !scanResult.getThreatIndicators().isEmpty()) {
                whatHappened.append("2. **Identified Threat Indicators:**\n");
                for (String ind : scanResult.getThreatIndicators()) {
                    whatHappened.append("   - ").append(ind).append("\n");
                }
            }
        } else {
            whatHappened.append("1. **Adversary Tactics:** Attackers construct convincing web portals that mimic reputable entities (banks, tech support, courier services) to trigger immediate psychological urgency.\n");
        }

        whatHappened.append("\n**How Your Data Was Accessed / Fetched:**\n");
        if (enteredCredentials) {
            whatHappened.append("- **Direct Form Interception:** Because credentials/information were entered on the landing page, the adversary's server immediately logged and stored those sensitive values in their database.\n");
        } else {
            whatHappened.append("- **Silent Browser Telemetry (No Typing Required):** Even if you did not type anything, simply opening a malicious webpage enables client-side scripts to extract your Public IP address, approximate geographical location, browser fingerprint (User-Agent, OS version, installed fonts, screen resolution), and HTTP Referer headers.\n");
        }
        whatHappened.append("- **Session & Cookie Vulnerability:** In cross-site scripting (XSS) or browser exploit scenarios, malicious scripts attempt to inspect `document.cookie`, active session tokens, or cached local storage to replicate your authenticated state.\n");
        whatHappened.append("- **Clipboard & Autofill Scraping:** Modern malicious phishing kits often poll HTML autofill cache to capture pre-saved emails, phone numbers, or addresses.\n");

        result.setWhatHappened(whatHappened.toString());

        // Compile Compromised Data Assessment
        List<String> compData = new ArrayList<>();
        if (enteredCredentials) {
            compData.add("🔴 Submitted Passwords, Usernames & Security Answers [HIGH RISK]");
        }
        if (financialInvolved) {
            compData.add("🔴 Banking / Payment Card / UPI Details [CRITICAL FINANCIAL RISK]");
        }
        compData.add("🟠 Active Browser Session Cookies & OAuth Tokens (Potential Account Takeover)");
        compData.add("🟡 Public IP Address & Network ISP Location");
        compData.add("🟡 Device & Browser Fingerprint (OS version, Browser Engine, Canvas Telemetry)");
        compData.add("🟡 Browser Autofill / Stored Form Information");
        if (downloadedFile) {
            compData.add("🔴 Local File System & Executable Storage (Potential Malware Dropper)");
        }
        result.setCompromisedDataItems(compData);

        // Compile Step-by-Step Emergency Remediation Plan
        List<String> actions = new ArrayList<>();
        actions.add("1. [CRITICAL] RESET PASSWORDS IMMEDIATELY from a separate clean device (do NOT reset from the device that opened the link until scanned).");
        actions.add("2. [CRITICAL] GLOBAL SESSION TERMINATION: Open Google, Microsoft, Apple, and Email account settings and click 'Log Out of All Devices / Revoke All Sessions'.");
        actions.add("3. [HIGH] ENABLE MULTI-FACTOR AUTHENTICATION (2FA): Switch to Authenticator App (Google Authenticator / Microsoft Authenticator) instead of SMS.");
        actions.add("4. [HIGH] PURGE BROWSER STATE: In your browser, open Settings -> Clear Browsing Data -> Select 'Cookies, Site Data, and Cached Images' for 'All Time'.");
        actions.add("5. [HIGH] REVOKE UNRECOGNIZED APPS & EXTENSIONS: Check your browser extensions and account OAuth connected apps. Delete anything unrecognized.");
        if (financialInvolved) {
            actions.add("6. [CRITICAL] NOTIFY BANK / FREEZE CARDS: Contact your bank's fraud helpline immediately to place a temporary block on cards or UPI IDs.");
        }
        actions.add("7. [MEDIUM] FULL ENDPOINT SCAN: Run a full system antivirus scan (Windows Defender / Malwarebytes) to verify no stealth trojan was dropped.");
        result.setEmergencyActions(actions);

        // Enterprise Containment Strategy
        StringBuilder containment = new StringBuilder();
        containment.append("SOC Containment Directives:\n");
        if (scanResult != null && scanResult.getDomain() != null && !scanResult.getDomain().isEmpty()) {
            containment.append("1. Block domain '").append(scanResult.getDomain()).append("' at perimeter DNS firewall and Web Gateway.\n");
            containment.append("2. Add IOC URL '").append(scanResult.getCleanUrl() != null ? scanResult.getCleanUrl() : extractedUrl).append("' to enterprise proxy blacklist.\n");
        } else {
            containment.append("1. Block reported threat indicators at perimeter gateway.\n");
        }
        containment.append("3. Invalidate Kerberos / Active Directory session tokens for affected user account.\n");
        containment.append("4. Isolate affected endpoint from corporate VLAN until clean AV scan verified.\n");
        result.setContainmentStrategy(containment.toString());

        // Determine Risk Score & Severity
        int finalScore = incident.getRiskScore();
        if (scanResult != null) {
            finalScore = Math.max(finalScore, scanResult.getRiskScore());
        }
        if (enteredCredentials || financialInvolved) {
            finalScore = Math.max(finalScore, 88);
        } else if (openedLink && scanResult != null && scanResult.getRiskScore() >= 40) {
            finalScore = Math.max(finalScore, 78);
        } else if (finalScore < 50) {
            finalScore = 65; // Default moderate risk for security incident inquiry
        }
        result.setAdjustedRiskScore(finalScore);

        String level;
        String sev;
        if (finalScore >= 85) {
            level = "CRITICAL";
            sev = "CRITICAL";
        } else if (finalScore >= 65) {
            level = "HIGH";
            sev = "HIGH";
        } else if (finalScore >= 40) {
            level = "MEDIUM";
            sev = "MEDIUM";
        } else {
            level = "LOW";
            sev = "LOW";
        }
        result.setAdjustedRiskLevel(level);
        result.setAdjustedSeverity(sev);

        // Enrich the incident record
        incident.setRootCause(result.getWhatHappened());
        
        StringBuilder recAction = new StringBuilder();
        recAction.append("🚨 EMERGENCY REMEDIATION ACTION PLAN:\n");
        for (String act : result.getEmergencyActions()) {
            recAction.append(act).append("\n");
        }
        recAction.append("\n⚠️ POTENTIALLY COMPROMISED DATA ASSETS:\n");
        for (String d : result.getCompromisedDataItems()) {
            recAction.append("- ").append(d).append("\n");
        }
        incident.setRecommendedAction(recAction.toString());

        incident.setContainmentPlan(result.getContainmentStrategy());
        incident.setRiskScore(finalScore);
        incident.setRiskLevel(level);
        if (incident.getSeverity() == null || "MEDIUM".equals(incident.getSeverity()) || "LOW".equals(incident.getSeverity())) {
            incident.setSeverity(sev);
        }

        if ((incident.getIocIndicators() == null || incident.getIocIndicators().trim().isEmpty()) && extractedUrl != null) {
            incident.setIocIndicators(extractedUrl);
        }

        return result;
    }

    /**
     * Extracts first valid URL, domain or IP pattern from raw text.
     */
    public static String extractUrl(String text) {
        if (text == null) return null;
        Matcher m = URL_REGEX.matcher(text);
        if (m.find()) {
            String found = m.group();
            // Trim trailing punctuation like dots or commas
            while (found.endsWith(".") || found.endsWith(",") || found.endsWith(")") || found.endsWith(";")) {
                found = found.substring(0, found.length() - 1);
            }
            return found;
        }
        return null;
    }
}
