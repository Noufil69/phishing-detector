package com.noufil.phishingdetector.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;

class ScoreAggregatorTest {

    private final ScoreAggregator aggregator = new ScoreAggregator(ScoringConfig.defaults());

    private static RiskFactor ran(String check, int score) {
        return RiskFactor.of(check, score, "reason");
    }

    private static RiskFactor skipped(String check) {
        return RiskFactor.unavailable(check, "could not run");
    }

    // ---------- basics ----------

    @Test
    void noFactorsIsLowWithZeroScore() {
        RiskScore result = aggregator.aggregate(List.of());
        assertEquals(0, result.totalScore());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void levelBoundaries() {
        assertEquals(RiskLevel.LOW, aggregator.levelFor(0));
        assertEquals(RiskLevel.LOW, aggregator.levelFor(24));
        assertEquals(RiskLevel.MEDIUM, aggregator.levelFor(25));
        assertEquals(RiskLevel.MEDIUM, aggregator.levelFor(59));
        assertEquals(RiskLevel.HIGH, aggregator.levelFor(60));
        assertEquals(RiskLevel.HIGH, aggregator.levelFor(100));
    }

    @Test
    void allZeroScoresStayLow() {
        RiskScore result = aggregator.aggregate(List.of(
                ran("Structural", 0), ran("Typosquat", 0), ran("SSL Certificate", 0),
                ran("Domain Age", 0), ran("Safe Browsing", 0)));
        assertEquals(0, result.totalScore());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void theFactorsAreKeptForTheBreakdown() {
        RiskScore result = aggregator.aggregate(List.of(ran("Typosquat", 10), skipped("Domain Age")));
        assertEquals(2, result.factors().size());
        assertEquals(2, result.checksTotal());
        assertEquals(1, result.checksRun());
    }

    // ---------- single signals ----------

    @Test
    void aKnownBadListingIsMaximum() {
        RiskScore result = aggregator.aggregate(List.of(ran("Safe Browsing", 100)));
        assertEquals(100, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void aLookalikeBrandAloneIsHigh() {
        RiskScore result = aggregator.aggregate(List.of(ran("Typosquat", 90)));
        assertEquals(81, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void oneCharacterAwayFromABrandAloneIsHigh() {
        RiskScore result = aggregator.aggregate(List.of(ran("Typosquat", 70)));
        assertEquals(63, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void anExpiredCertificateAloneIsMedium() {
        RiskScore result = aggregator.aggregate(List.of(ran("SSL Certificate", 70)));
        assertEquals(56, result.totalScore());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void aCertificateForTheWrongHostAloneIsHigh() {
        RiskScore result = aggregator.aggregate(List.of(ran("SSL Certificate", 80)));
        assertEquals(64, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void aBrandNewDomainAloneIsMedium() {
        RiskScore result = aggregator.aggregate(List.of(ran("Domain Age", 85)));
        assertEquals(51, result.totalScore());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void aUrlShortenerAloneIsStillLow() {
        RiskScore result = aggregator.aggregate(List.of(ran("Structural", 25)));
        assertEquals(15, result.totalScore());
        assertEquals(RiskLevel.LOW, result.level());
    }

    // ---------- combining signals ----------

    @Test
    void severalSignalsTogetherBeatEachAlone() {
        RiskScore age = aggregator.aggregate(List.of(ran("Domain Age", 70)));
        RiskScore name = aggregator.aggregate(List.of(ran("Typosquat", 50)));
        RiskScore both = aggregator.aggregate(List.of(ran("Domain Age", 70), ran("Typosquat", 50)));

        assertEquals(RiskLevel.MEDIUM, age.level());
        assertEquals(RiskLevel.MEDIUM, name.level());
        assertEquals(68, both.totalScore());
        assertEquals(RiskLevel.HIGH, both.level());
    }

    @Test
    void aPlainHttpSiteWithoutHttpsIsMedium() {
        // Structural 10 (plain http) and SSL 30 (no https): worth a warning, not an alarm.
        RiskScore result = aggregator.aggregate(List.of(ran("Structural", 10), ran("SSL Certificate", 30)));
        assertEquals(29, result.totalScore());
        assertEquals(RiskLevel.MEDIUM, result.level());
    }

    @Test
    void totalNeverPassesOneHundred() {
        RiskScore result = aggregator.aggregate(List.of(
                ran("Structural", 100), ran("Typosquat", 100), ran("SSL Certificate", 100),
                ran("Domain Age", 100), ran("Safe Browsing", 100)));
        assertEquals(100, result.totalScore());
        assertEquals(RiskLevel.HIGH, result.level());
    }

    @Test
    void theOrderOfTheChecksDoesNotMatter() {
        List<RiskFactor> factors = new ArrayList<>(List.of(
                ran("Structural", 40), ran("Typosquat", 50), ran("SSL Certificate", 30), ran("Domain Age", 45)));
        int first = aggregator.aggregate(factors).totalScore();
        Collections.reverse(factors);
        assertEquals(first, aggregator.aggregate(factors).totalScore());
    }

    @Test
    void addingASignalNeverLowersTheScore() {
        int before = aggregator.aggregate(List.of(ran("Typosquat", 50))).totalScore();
        int after = aggregator.aggregate(List.of(ran("Typosquat", 50), ran("Structural", 10))).totalScore();
        assertTrue(after >= before);
    }

    // ---------- checks that could not run ----------

    @Test
    void unavailableChecksAreLeftOutNotCountedAsSafeOrDangerous() {
        RiskScore withSkips = aggregator.aggregate(List.of(
                ran("Typosquat", 70), skipped("Domain Age"), skipped("Safe Browsing")));
        RiskScore without = aggregator.aggregate(List.of(ran("Typosquat", 70)));
        assertEquals(without.totalScore(), withSkips.totalScore());
        assertEquals(1, withSkips.checksRun());
        assertEquals(3, withSkips.checksTotal());
    }

    @Test
    void whenNothingCouldRunTheScoreIsZeroAndTheResultSaysSo() {
        RiskScore result = aggregator.aggregate(List.of(skipped("Typosquat"), skipped("Domain Age")));
        assertEquals(0, result.totalScore());
        assertEquals(0, result.checksRun());
        assertEquals(2, result.checksTotal());
    }

    // ---------- weights and settings ----------

    @Test
    void aCheckWeNeverHeardOfUsesTheDefaultWeight() {
        RiskScore result = aggregator.aggregate(List.of(ran("Brand New Check", 60)));
        assertEquals(30, result.totalScore());
    }

    @Test
    void aZeroWeightSwitchesACheckOff() {
        ScoringConfig config = new ScoringConfig(Map.of("typosquat", 0.0), 0.5, 25, 60);
        RiskScore result = new ScoreAggregator(config).aggregate(List.of(ran("Typosquat", 100)));
        assertEquals(0, result.totalScore());
        assertEquals(RiskLevel.LOW, result.level());
    }

    @Test
    void customThresholdsMoveTheLevels() {
        ScoringConfig config = new ScoringConfig(Map.of("typosquat", 0.9), 0.5, 10, 90);
        ScoreAggregator custom = new ScoreAggregator(config);
        assertEquals(RiskLevel.MEDIUM, custom.aggregate(List.of(ran("Typosquat", 90))).level());
        assertEquals(RiskLevel.LOW, custom.aggregate(List.of(ran("Typosquat", 5))).level());
    }
}