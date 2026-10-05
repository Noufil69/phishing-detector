package com.noufil.phishingdetector.service;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScoreAggregatorTest {

    private final ScoreAggregator aggregator = new ScoreAggregator();

    @Test
    void noFactors_isLowWithZeroScore() {
        RiskScore result = aggregator.aggregate(List.of());

        assertEquals(0, result.totalScore());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void levelBoundaries() {
        assertEquals(RiskLevel.LOW, aggregator.levelFor(0));
        assertEquals(RiskLevel.LOW, aggregator.levelFor(29));
        assertEquals(RiskLevel.MEDIUM, aggregator.levelFor(30));
        assertEquals(RiskLevel.MEDIUM, aggregator.levelFor(59));
        assertEquals(RiskLevel.HIGH, aggregator.levelFor(60));
        assertEquals(RiskLevel.HIGH, aggregator.levelFor(100));
    }

    @Test
    void sumsScoresOfAvailableChecksOnly() {
        List<RiskFactor> factors = List.of(
                RiskFactor.of("A", 20, "reason a"),
                RiskFactor.of("B", 15, "reason b"),
                RiskFactor.unavailable("C", "could not run"));

        RiskScore result = aggregator.aggregate(factors);

        assertEquals(35, result.totalScore());
        assertEquals(RiskLevel.MEDIUM, result.level());
        assertEquals(3, result.factors().size());
    }

    @Test
    void totalIsCappedAt100() {
        List<RiskFactor> factors = List.of(
                RiskFactor.of("A", 80, "reason a"),
                RiskFactor.of("B", 90, "reason b"));

        RiskScore result = aggregator.aggregate(factors);

        assertEquals(100, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }
}