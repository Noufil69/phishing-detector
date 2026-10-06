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

    /** How many checks actually produced a result. */
    public int checksRun() {
        return (int) factors.stream().filter(RiskFactor::available).count();
    }

    /** How many checks were attempted, including the ones that could not run. */
    public int checksTotal() {
        return factors.size();
    }
}