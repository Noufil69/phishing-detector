package com.noufil.phishingdetector.controller;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;

class CheckResponseTest {

    private static RiskScore score(int total, RiskLevel level, RiskFactor... factors) {
        return new RiskScore(total, level, List.of(factors));
    }

    @Test
    void copiesTheScoreLevelHostAndBreakdown() {
        RiskScore result = score(63, RiskLevel.HIGH,
                RiskFactor.of("Typosquat", 70, "one character away"),
                RiskFactor.unavailable("Domain Age", "no data"));

        CheckResponse response = CheckResponse.from(result, "paypa1.com");

        assertEquals(RiskLevel.HIGH, response.level());
        assertEquals(63, response.score());
        assertEquals("paypa1.com", response.host());
        assertEquals(2, response.factors().size());

        CheckResponse.FactorView first = response.factors().get(0);
        assertEquals("Typosquat", first.check());
        assertEquals(70, first.score());
        assertEquals("one character away", first.reason());
        assertTrue(first.available());

        CheckResponse.FactorView second = response.factors().get(1);
        assertEquals("Domain Age", second.check());
        assertFalse(second.available());
    }

    @Test
    void lowDoesNotPromiseSafety() {
        CheckResponse response = CheckResponse.from(
                score(0, RiskLevel.LOW, RiskFactor.of("Structural", 0, "fine")), "example.com");
        assertTrue(response.summary().contains("does not guarantee"));
    }

    @Test
    void mediumAndHighSummariesDiffer() {
        RiskFactor f = RiskFactor.of("Structural", 10, "r");
        String medium = CheckResponse.from(score(40, RiskLevel.MEDIUM, f), "a.example").summary();
        String high = CheckResponse.from(score(80, RiskLevel.HIGH, f), "a.example").summary();
        assertTrue(medium.contains("Be careful"));
        assertTrue(high.contains("Do not enter passwords"));
        assertFalse(medium.equals(high));
    }

    @Test
    void noNoteWhenEveryCheckRan() {
        CheckResponse response = CheckResponse.from(score(0, RiskLevel.LOW,
                RiskFactor.of("A", 0, "r"), RiskFactor.of("B", 0, "r")), "a.example");
        assertNull(response.note());
        assertEquals(2, response.checksRun());
        assertEquals(2, response.checksTotal());
    }

    @Test
    void aNoteSaysHowManyChecksRanWhenSomeCouldNot() {
        CheckResponse response = CheckResponse.from(score(0, RiskLevel.LOW,
                RiskFactor.of("A", 0, "r"), RiskFactor.unavailable("B", "r"),
                RiskFactor.unavailable("C", "r")), "a.example");
        assertEquals("Only 1 of 3 checks could run, so this result is less complete.", response.note());
        assertEquals(1, response.checksRun());
        assertEquals(3, response.checksTotal());
    }

    @Test
    void whenNothingRanTheSummaryAdmitsThereIsNoResult() {
        CheckResponse response = CheckResponse.from(score(0, RiskLevel.LOW,
                RiskFactor.unavailable("A", "r"), RiskFactor.unavailable("B", "r")), "a.example");
        assertTrue(response.summary().contains("no result"));
        assertFalse(response.summary().contains("No strong warning signs"));
    }

    @Test
    void noChecksAtAllAlsoAdmitsThereIsNoResult() {
        CheckResponse response = CheckResponse.from(score(0, RiskLevel.LOW), "a.example");
        assertTrue(response.summary().contains("no result"));
        assertEquals(0, response.checksTotal());
    }
}