package com.noufil.phishingdetector.service;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Turns the per-check results into one overall score and risk level.
 *
 * <p>Phase 1 uses a simple placeholder formula: sum the scores of the checks
 * that ran, cap at 100, then map to a level. Phase 7 replaces this with the
 * real weighting and the fair handling of unavailable checks.
 */
@Component
public class ScoreAggregator {

    static final int MAX_SCORE = 100;
    static final int MEDIUM_THRESHOLD = 30;
    static final int HIGH_THRESHOLD = 60;

    public RiskScore aggregate(List<RiskFactor> factors) {
        int total = factors.stream()
                .filter(RiskFactor::available)
                .mapToInt(RiskFactor::score)
                .sum();
        total = Math.min(total, MAX_SCORE);
        return new RiskScore(total, levelFor(total), factors);
    }

    RiskLevel levelFor(int totalScore) {
        if (totalScore >= HIGH_THRESHOLD) {
            return RiskLevel.HIGH;
        }
        if (totalScore >= MEDIUM_THRESHOLD) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }
}