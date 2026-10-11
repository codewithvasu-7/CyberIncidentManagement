package com.cyberincident.security;

/**
 * Multi-factor Quantitative Risk Calculator.
 * Implements cybersecurity risk equation:
 * Risk Score = (Threat Weight * 0.35 + Asset Criticality * 0.25 + Scope * 0.20 + Data Sensitivity * 0.20) * 100
 */
public class RiskCalculator {

    public static class RiskAssessment {
        private final int score;
        private final String level; // LOW, MEDIUM, HIGH, CRITICAL

        public RiskAssessment(int score, String level) {
            this.score = score;
            this.level = level;
        }

        public int getScore() {
            return score;
        }

        public String getLevel() {
            return level;
        }
    }

    /**
     * Calculates risk score and assigns qualitative risk level.
     */
    public static RiskAssessment calculate(String category, String affectedSystem, String impactScope, String dataSensitivity) {
        double threatWeight = RiskAnalyzer.evaluateCategoryWeight(category);
        double assetWeight = RiskAnalyzer.evaluateSystemCriticality(affectedSystem);
        double scopeWeight = RiskAnalyzer.evaluateScopeWeight(impactScope);
        double dataWeight = RiskAnalyzer.evaluateDataSensitivityWeight(dataSensitivity);

        // Weighted risk formula (0 to 100)
        double compositeScore = (threatWeight * 0.35 + assetWeight * 0.25 + scopeWeight * 0.20 + dataWeight * 0.20) * 100.0;
        int score = (int) Math.round(compositeScore);
        if (score < 0) score = 0;
        if (score > 100) score = 100;

        String level;
        if (score >= 85) {
            level = "CRITICAL";
        } else if (score >= 65) {
            level = "HIGH";
        } else if (score >= 40) {
            level = "MEDIUM";
        } else {
            level = "LOW";
        }

        return new RiskAssessment(score, level);
    }

    /**
     * Recommends suggested severity if user did not choose, or validates severity.
     */
    public static String getRecommendedSeverity(int riskScore) {
        if (riskScore >= 85) return "CRITICAL";
        if (riskScore >= 65) return "HIGH";
        if (riskScore >= 40) return "MEDIUM";
        return "LOW";
    }
}
