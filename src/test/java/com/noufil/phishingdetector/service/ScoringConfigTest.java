package com.noufil.phishingdetector.service;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ScoringConfigTest {

    private static ScoringConfig from(Map<String, String> properties) {
        return ScoringConfig.fromProperties(properties::get);
    }

    @Test
    void keysAreLowerCaseWithDashes() {
        assertEquals("ssl-certificate", ScoringConfig.keyFor("SSL Certificate"));
        assertEquals("domain-age", ScoringConfig.keyFor("Domain Age"));
        assertEquals("safe-browsing", ScoringConfig.keyFor("Safe Browsing"));
        assertEquals("structural", ScoringConfig.keyFor("Structural"));
        assertEquals("a-b", ScoringConfig.keyFor("  A / B  "));
    }

    @Test
    void defaultsKnowEveryBuiltInCheck() {
        ScoringConfig config = ScoringConfig.defaults();
        assertEquals(1.0, config.weightFor("Safe Browsing"));
        assertEquals(0.9, config.weightFor("Typosquat"));
        assertEquals(0.8, config.weightFor("SSL Certificate"));
        assertEquals(0.6, config.weightFor("Domain Age"));
        assertEquals(0.6, config.weightFor("Structural"));
        assertEquals(25, config.mediumThreshold());
        assertEquals(60, config.highThreshold());
    }

    @Test
    void unknownChecksGetTheDefaultWeight() {
        assertEquals(0.5, ScoringConfig.defaults().weightFor("Something New"));
    }

    @Test
    void noPropertiesMeansDefaults() {
        ScoringConfig config = from(new HashMap<>());
        assertEquals(0.9, config.weightFor("Typosquat"));
        assertEquals(25, config.mediumThreshold());
        assertEquals(60, config.highThreshold());
    }

    @Test
    void propertiesOverrideDefaults() {
        Map<String, String> p = new HashMap<>();
        p.put("scoring.weight.typosquat", "0.4");
        p.put("scoring.default-weight", "0.7");
        p.put("scoring.medium-threshold", "30");
        p.put("scoring.high-threshold", "70");
        ScoringConfig config = from(p);
        assertEquals(0.4, config.weightFor("Typosquat"));
        assertEquals(0.7, config.weightFor("Something New"));
        assertEquals(0.6, config.weightFor("Domain Age"));
        assertEquals(30, config.mediumThreshold());
        assertEquals(70, config.highThreshold());
    }

    @Test
    void blankPropertiesKeepTheDefault() {
        Map<String, String> p = new HashMap<>();
        p.put("scoring.weight.typosquat", "   ");
        p.put("scoring.high-threshold", "");
        ScoringConfig config = from(p);
        assertEquals(0.9, config.weightFor("Typosquat"));
        assertEquals(60, config.highThreshold());
    }

    @Test
    void valuesWithSpacesAroundThemAreAccepted() {
        ScoringConfig config = from(Map.of("scoring.weight.typosquat", " 0.3 ", "scoring.high-threshold", " 80 "));
        assertEquals(0.3, config.weightFor("Typosquat"));
        assertEquals(80, config.highThreshold());
    }

    @Test
    void unusableWeightsStopTheAppAndNameTheProperty() {
        for (String bad : new String[] {"abc", "1.5", "-0.1", "NaN"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> from(Map.of("scoring.weight.typosquat", bad)));
            assertTrue(e.getMessage().contains("scoring.weight.typosquat"), bad);
        }
    }

    @Test
    void unusableThresholdsStopTheAppAndNameTheProperty() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> from(Map.of("scoring.medium-threshold", "lots")));
        assertTrue(e.getMessage().contains("scoring.medium-threshold"));
    }

    @Test
    void thresholdsMustBeInOrderAndInRange() {
        assertThrows(IllegalArgumentException.class,
                () -> from(Map.of("scoring.medium-threshold", "60", "scoring.high-threshold", "60")));
        assertThrows(IllegalArgumentException.class,
                () -> from(Map.of("scoring.medium-threshold", "70", "scoring.high-threshold", "60")));
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("scoring.medium-threshold", "0")));
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("scoring.high-threshold", "101")));
    }

    @Test
    void constructorRejectsBadWeights() {
        assertThrows(IllegalArgumentException.class, () -> new ScoringConfig(Map.of("a", 2.0), 0.5, 25, 60));
        assertThrows(IllegalArgumentException.class, () -> new ScoringConfig(Map.of(), -1.0, 25, 60));
    }

    @Test
    void settingsMapIsCopiedSoLaterChangesDoNotLeakIn() {
        Map<String, Double> weights = new HashMap<>(Map.of("typosquat", 0.9));
        ScoringConfig config = new ScoringConfig(weights, 0.5, 25, 60);
        weights.put("typosquat", 0.1);
        assertEquals(0.9, config.weightFor("Typosquat"));
        assertFalse(weights.isEmpty());
    }
}