package com.cyberincident.security;

import java.util.Locale;

/**
 * Security Risk Analyzer that evaluates context factors of an incident:
 * - Threat Category Weight
 * - Asset Criticality
 * - Impact Scope
 * - Data Sensitivity
 */
public class RiskAnalyzer {

    /**
     * Determines threat vector score weight (0.0 to 1.0) based on category.
     */
    public static double evaluateCategoryWeight(String category) {
        if (category == null) return 0.50;
        String cat = category.trim().toUpperCase(Locale.ROOT);
        switch (cat) {
            case "RANSOMWARE":
                return 1.00;
            case "DATA BREACH":
            case "DATA_BREACH":
                return 0.95;
            case "INSIDER THREAT":
            case "INSIDER_THREAT":
                return 0.85;
            case "DDOS":
                return 0.80;
            case "MALWARE":
                return 0.75;
            case "PHISHING":
                return 0.70;
            case "UNAUTHORIZED ACCESS":
            case "UNAUTHORIZED_ACCESS":
                return 0.65;
            case "SOCIAL ENGINEERING":
            case "SOCIAL_ENGINEERING":
                return 0.60;
            default:
                return 0.45;
        }
    }

    /**
     * Determines asset criticality weight (0.0 to 1.0) from affected system.
     */
    public static double evaluateSystemCriticality(String affectedSystem) {
        if (affectedSystem == null) return 0.50;
        String sys = affectedSystem.toLowerCase(Locale.ROOT);
        if (sys.contains("database") || sys.contains("db") || sys.contains("domain") || 
            sys.contains("active directory") || sys.contains("nas") || sys.contains("core") ||
            sys.contains("production") || sys.contains("cluster")) {
            return 1.00;
        } else if (sys.contains("payment") || sys.contains("finance") || sys.contains("api") ||
                   sys.contains("gateway") || sys.contains("portal") || sys.contains("server")) {
            return 0.80;
        } else if (sys.contains("mailbox") || sys.contains("workstation") || sys.contains("laptop") ||
                   sys.contains("endpoint") || sys.contains("vpn")) {
            return 0.60;
        } else if (sys.contains("staging") || sys.contains("test") || sys.contains("dev") ||
                   sys.contains("sandbox")) {
            return 0.35;
        }
        return 0.50;
    }

    /**
     * Evaluates scope of impact (0.0 to 1.0).
     */
    public static double evaluateScopeWeight(String impactScope) {
        if (impactScope == null) return 0.50;
        String scope = impactScope.trim().toUpperCase(Locale.ROOT);
        switch (scope) {
            case "ORGANIZATION-WIDE":
            case "ORGANIZATION_WIDE":
                return 1.00;
            case "EXTERNAL/CLIENT":
            case "EXTERNAL_CLIENT":
                return 0.85;
            case "DEPARTMENT":
                return 0.60;
            case "INDIVIDUAL":
                return 0.30;
            default:
                return 0.50;
        }
    }

    /**
     * Evaluates data sensitivity weight (0.0 to 1.0).
     */
    public static double evaluateDataSensitivityWeight(String dataSensitivity) {
        if (dataSensitivity == null) return 0.50;
        String sens = dataSensitivity.trim().toUpperCase(Locale.ROOT);
        if (sens.contains("HIGH") || sens.contains("PII") || sens.contains("CRITICAL")) {
            return 1.00;
        } else if (sens.contains("CONFIDENTIAL") || sens.contains("RESTRICTED")) {
            return 0.80;
        } else if (sens.contains("INTERNAL")) {
            return 0.50;
        } else if (sens.contains("PUBLIC")) {
            return 0.20;
        }
        return 0.50;
    }
}
