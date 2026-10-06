package com.noufil.phishingdetector.service;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * The tuning numbers for the final score: how much each check is trusted, and
 * where the Low / Medium / High lines sit.
 *
 * Weights run from 0.0 (ignore this check) to 1.0 (take its score at face value).
 * Every default lives here in code. Any of them can be overridden in
 * application.properties or an environment variable, for example
 * scoring.weight.typosquat=0.8 or SCORING_HIGH_THRESHOLD=65.
 */
public final class ScoringConfig {

    static final double DEFAULT_WEIGHT_FOR_UNKNOWN_CHECKS = 0.5;
    static final int DEFAULT_MEDIUM_THRESHOLD = 25;
    static final int DEFAULT_HIGH_THRESHOLD = 60;

    /** Check key (see keyFor) to default weight. */
    static final Map<String, Double> DEFAULT_WEIGHTS;

    static {
        Map<String, Double> m = new LinkedHashMap<>();
        // A listing on Google's lists is a known bad site, not a guess.
        m.put("safe-browsing", 1.0);
        // Imitating a known brand is the most telling sign of phishing we can see by ourselves.
        m.put("typosquat", 0.9);
        // A broken certificate is serious, but plenty of honest sites have sloppy certificates.
        m.put("ssl-certificate", 0.8);
        // Young domains are suspicious, but every new honest site is young too.
        m.put("domain-age", 0.6);
        // Odd-looking addresses are common on honest sites, so these signals are the weakest.
        m.put("structural", 0.6);
        DEFAULT_WEIGHTS = Map.copyOf(m);
    }

    private final Map<String, Double> weights;
    private final double defaultWeight;
    private final int mediumThreshold;
    private final int highThreshold;

    public ScoringConfig(Map<String, Double> weights, double defaultWeight, int mediumThreshold, int highThreshold) {
        for (double w : weights.values()) {
            checkWeight(w);
        }
        checkWeight(defaultWeight);
        if (mediumThreshold < 1 || highThreshold > 100 || mediumThreshold >= highThreshold) {
            throw new IllegalArgumentException("Thresholds must satisfy 1 <= medium < high <= 100");
        }
        this.weights = Map.copyOf(weights);
        this.defaultWeight = defaultWeight;
        this.mediumThreshold = mediumThreshold;
        this.highThreshold = highThreshold;
    }

    public static ScoringConfig defaults() {
        return new ScoringConfig(DEFAULT_WEIGHTS, DEFAULT_WEIGHT_FOR_UNKNOWN_CHECKS,
                DEFAULT_MEDIUM_THRESHOLD, DEFAULT_HIGH_THRESHOLD);
    }

    /**
     * Builds the settings from a property lookup (the Spring environment in the
     * running app, a plain map in tests). A missing or blank property keeps the
     * default. A property that is present but not usable stops the app at startup
     * with a message naming the property, instead of quietly scoring wrongly.
     */
    public static ScoringConfig fromProperties(Function<String, String> lookup) {
        Map<String, Double> weights = new LinkedHashMap<>();
        for (Map.Entry<String, Double> entry : DEFAULT_WEIGHTS.entrySet()) {
            String property = "scoring.weight." + entry.getKey();
            weights.put(entry.getKey(), readDouble(lookup, property, entry.getValue()));
        }
        double defaultWeight = readDouble(lookup, "scoring.default-weight", DEFAULT_WEIGHT_FOR_UNKNOWN_CHECKS);
        int medium = readInt(lookup, "scoring.medium-threshold", DEFAULT_MEDIUM_THRESHOLD);
        int high = readInt(lookup, "scoring.high-threshold", DEFAULT_HIGH_THRESHOLD);
        return new ScoringConfig(weights, defaultWeight, medium, high);
    }

    /** "SSL Certificate" becomes "ssl-certificate": lower case, runs of other characters turned into one dash. */
    public static String keyFor(String checkName) {
        String key = checkName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
        return key.replaceAll("^-+|-+$", "");
    }

    public double weightFor(String checkName) {
        return weights.getOrDefault(keyFor(checkName), defaultWeight);
    }

    public int mediumThreshold() {
        return mediumThreshold;
    }

    public int highThreshold() {
        return highThreshold;
    }

    private static void checkWeight(double weight) {
        if (Double.isNaN(weight) || weight < 0.0 || weight > 1.0) {
            throw new IllegalArgumentException("Weights must be between 0.0 and 1.0");
        }
    }

    private static double readDouble(Function<String, String> lookup, String property, double fallback) {
        String text = lookup.apply(property);
        if (text == null || text.isBlank()) {
            return fallback;
        }
        try {
            double value = Double.parseDouble(text.trim());
            checkWeight(value);
            return value;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid scoring setting: " + property);
        }
    }

    private static int readInt(Function<String, String> lookup, String property, int fallback) {
        String text = lookup.apply(property);
        if (text == null || text.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid scoring setting: " + property);
        }
    }
}