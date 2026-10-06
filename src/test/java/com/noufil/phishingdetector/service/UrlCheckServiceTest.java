package com.noufil.phishingdetector.service;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.HeuristicCheck;
import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;

class UrlCheckServiceTest {

    /** Simple stand-in heuristic that returns a fixed score. */
    private static class FixedCheck implements HeuristicCheck {
        private final String name;
        private final int score;

        FixedCheck(String name, int score) {
            this.name = name;
            this.score = score;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public RiskFactor evaluate(String url) {
            return RiskFactor.of(name, score, "fixed result for testing");
        }
    }

    /** Stand-in heuristic that always blows up. */
    private static class ExplodingCheck implements HeuristicCheck {
        @Override
        public String getName() {
            return "Exploding check";
        }

        @Override
        public RiskFactor evaluate(String url) {
            throw new IllegalStateException("boom");
        }
    }

    @Test
    void noChecksRegistered_returnsLowRisk() {
        UrlCheckService service = new UrlCheckService(List.of(), new ScoreAggregator(ScoringConfig.defaults()));

        RiskScore result = service.analyze("https://example.com");

        assertNotNull(result);
        assertEquals(RiskLevel.LOW, result.level());
        assertEquals(0, result.totalScore());
        assertTrue(result.factors().isEmpty());
    }

    @Test
    void runsEveryCheckAndAggregates() {
        UrlCheckService service = new UrlCheckService(
                List.of(new FixedCheck("Domain Age", 70), new FixedCheck("Typosquat", 50)),
                new ScoreAggregator(ScoringConfig.defaults()));

        RiskScore result = service.analyze("https://example.com");

        assertEquals(68, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
        assertEquals(2, result.factors().size());
    }

    @Test
    void failingCheckIsMarkedUnavailable_andOthersStillRun() {
        UrlCheckService service = new UrlCheckService(
                List.of(new ExplodingCheck(), new FixedCheck("Domain Age", 70)),
                new ScoreAggregator(ScoringConfig.defaults()));

        RiskScore result = service.analyze("https://example.com");

        assertEquals(2, result.factors().size());
        assertFalse(result.factors().get(0).available());
        assertTrue(result.factors().get(1).available());
        assertEquals(42, result.totalScore());
        assertEquals(1, result.checksRun());
        assertEquals(2, result.checksTotal());
    }

    @Test
    void blankUrlIsRejected() {
        UrlCheckService service = new UrlCheckService(List.of(), new ScoreAggregator(ScoringConfig.defaults()));

        assertThrows(IllegalArgumentException.class, () -> service.analyze(" "));
        assertThrows(IllegalArgumentException.class, () -> service.analyze(null));
    }
}