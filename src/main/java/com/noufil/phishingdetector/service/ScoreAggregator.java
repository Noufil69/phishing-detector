package com.noufil.phishingdetector.service;

import java.util.List;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;

/**
 * Turns the per-check results into one overall score and risk level.
 *
 * How the score is built:
 *  - Each check that ran gives a score from 0 to 100. That score is multiplied by the
 *    check's weight (how far we trust it) and read as "the chance this URL is bad".
 *  - The chances are combined the way independent warning signs combine: the URL is
 *    only clean if EVERY signal is wrong. total = 1 - (1 - p1) * (1 - p2) * ...
 *  - One strong signal can therefore reach High on its own, and several weak signals
 *    add up, but the total can never go past 100 and never double counts.
 *  - A check that could not run is left out. It neither raises nor lowers the score.
 *    The caller can see how many checks ran from the result itself.
 *
 * The weights and the Low / Medium / High lines come from ScoringConfig.
 */
@Component
public class ScoreAggregator {

    static final int MAX_SCORE = 100;

    private final ScoringConfig config;

    public ScoreAggregator(ScoringConfig config) {
        this.config = config;
    }

    public RiskScore aggregate(List<RiskFactor> factors) {
        double stillClean = 1.0;
        for (RiskFactor factor : factors) {
            if (!factor.available()) {
                continue;
            }
            double chance = config.weightFor(factor.checkName()) * factor.score() / MAX_SCORE;
            stillClean *= 1.0 - Math.min(1.0, Math.max(0.0, chance));
        }
        int total = (int) Math.round((1.0 - stillClean) * MAX_SCORE);
        total = Math.min(MAX_SCORE, Math.max(0, total));
        return new RiskScore(total, levelFor(total), factors);
    }

    RiskLevel levelFor(int totalScore) {
        if (totalScore >= config.highThreshold()) {
            return RiskLevel.HIGH;
        }
        if (totalScore >= config.mediumThreshold()) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }
}