package com.cyberincident.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Model representing the result of an automated URL / QR Code Threat Analysis.
 */
public class UrlScanResult implements Serializable {
    private static final long serialVersionUID = 1L;

    private String originalUrl;
    private String cleanUrl;
    private String protocol;
    private String domain;
    private int riskScore; // 0 (Safe) to 100 (Critical Malicious)
    private String threatLevel; // SAFE, SUSPICIOUS, MALICIOUS, PHISHING
    private String summary;
    private List<String> threatIndicators = new ArrayList<>();
    private List<String> safetyFactors = new ArrayList<>();
    private boolean isPhishing;
    private boolean isMalware;
    private boolean isQuishing; // QR Code Phishing
    private String recommendedAction;

    // External Multi-Engine Threat Feeds
    private String virusTotalScore; // e.g. "18/72 engines flagged"
    private String virusTotalVerdict; // e.g. "MALICIOUS"
    private String abuseIpScore; // e.g. "Abuse Confidence: 87%"
    private String abuseIpCountry; // e.g. "RU - Russian Federation"
    private String googleSafeBrowsingVerdict; // e.g. "FLAGGED: SOCIAL_ENGINEERING / PHISHING"
    private boolean externalFeedsEnabled;

    public String getVirusTotalScore() { return virusTotalScore; }
    public void setVirusTotalScore(String virusTotalScore) { this.virusTotalScore = virusTotalScore; }

    public String getVirusTotalVerdict() { return virusTotalVerdict; }
    public void setVirusTotalVerdict(String virusTotalVerdict) { this.virusTotalVerdict = virusTotalVerdict; }

    public String getAbuseIpScore() { return abuseIpScore; }
    public void setAbuseIpScore(String abuseIpScore) { this.abuseIpScore = abuseIpScore; }

    public String getAbuseIpCountry() { return abuseIpCountry; }
    public void setAbuseIpCountry(String abuseIpCountry) { this.abuseIpCountry = abuseIpCountry; }

    public String getGoogleSafeBrowsingVerdict() { return googleSafeBrowsingVerdict; }
    public void setGoogleSafeBrowsingVerdict(String googleSafeBrowsingVerdict) { this.googleSafeBrowsingVerdict = googleSafeBrowsingVerdict; }

    public boolean isExternalFeedsEnabled() { return externalFeedsEnabled; }
    public void setExternalFeedsEnabled(boolean externalFeedsEnabled) { this.externalFeedsEnabled = externalFeedsEnabled; }

    public UrlScanResult() {
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public void setOriginalUrl(String originalUrl) {
        this.originalUrl = originalUrl;
    }

    public String getCleanUrl() {
        return cleanUrl;
    }

    public void setCleanUrl(String cleanUrl) {
        this.cleanUrl = cleanUrl;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getThreatLevel() {
        return threatLevel;
    }

    public void setThreatLevel(String threatLevel) {
        this.threatLevel = threatLevel;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getThreatIndicators() {
        return threatIndicators;
    }

    public void setThreatIndicators(List<String> threatIndicators) {
        this.threatIndicators = threatIndicators;
    }

    public void addThreatIndicator(String indicator) {
        this.threatIndicators.add(indicator);
    }

    public List<String> getSafetyFactors() {
        return safetyFactors;
    }

    public void setSafetyFactors(List<String> safetyFactors) {
        this.safetyFactors = safetyFactors;
    }

    public void addSafetyFactor(String factor) {
        this.safetyFactors.add(factor);
    }

    public boolean isPhishing() {
        return isPhishing;
    }

    public void setPhishing(boolean phishing) {
        isPhishing = phishing;
    }

    public boolean isMalware() {
        return isMalware;
    }

    public void setMalware(boolean malware) {
        isMalware = malware;
    }

    public boolean isQuishing() {
        return isQuishing;
    }

    public void setQuishing(boolean quishing) {
        isQuishing = quishing;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }

    public String getBadgeClass() {
        if ("MALICIOUS".equalsIgnoreCase(threatLevel) || "PHISHING".equalsIgnoreCase(threatLevel)) {
            return "badge-critical";
        } else if ("SUSPICIOUS".equalsIgnoreCase(threatLevel)) {
            return "badge-high";
        }
        return "badge-resolved";
    }
}
