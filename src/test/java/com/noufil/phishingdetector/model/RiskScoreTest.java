package com.noufil.phishingdetector.model;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class RiskScoreTest {

    @Test
    void countsChecksThatRanAndChecksAttempted() {
        RiskScore score = new RiskScore(10, RiskLevel.LOW, List.of(
                RiskFactor.of("A", 10, "r"),
                RiskFactor.unavailable("B", "r"),
                RiskFactor.of("C", 0, "r")));
        assertEquals(2, score.checksRun());
        assertEquals(3, score.checksTotal());
    }

    @Test
    void emptyResultCountsZero() {
        RiskScore score = new RiskScore(0, RiskLevel.LOW, List.of());
        assertEquals(0, score.checksRun());
        assertEquals(0, score.checksTotal());
    }

    @Test
    void factorsAreCopiedSoLaterChangesDoNotLeakIn() {
        List<RiskFactor> factors = new ArrayList<>(List.of(RiskFactor.of("A", 1, "r")));
        RiskScore score = new RiskScore(1, RiskLevel.LOW, factors);
        factors.add(RiskFactor.of("B", 1, "r"));
        assertEquals(1, score.checksTotal());
    }

    @Test
    void invalidValuesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new RiskScore(-1, RiskLevel.LOW, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new RiskScore(101, RiskLevel.HIGH, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new RiskScore(5, null, List.of()));
    }
}