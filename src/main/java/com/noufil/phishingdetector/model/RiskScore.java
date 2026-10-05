package com.noufil.phishingdetector.model;

import java.util.List;

/** The final result for one URL: overall score, risk level, and the per-check breakdown. */
public record RiskScore(int totalScore, RiskLevel level, List<RiskFactor> factors) {

    public RiskScore {
        if (totalScore < 0 || totalScore > 100) {
            throw new IllegalArgumentException("totalScore must be between 0 and 100");
        }
        if (level == null) {
            throw new IllegalArgumentException("level must not be null");
        }
        factors = List.copyOf(factors);
    }
}