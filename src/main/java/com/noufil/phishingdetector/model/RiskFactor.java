package com.noufil.phishingdetector.model;

/**
 * The result of one heuristic check: how much risk it adds, and why.
 *
 * <p>{@code available} is false when a check could not run (timeout, API down,
 * unexpected error). That is different from "ran and found nothing", which is
 * available = true with score 0. This lets the app degrade gracefully instead
 * of crashing or silently treating a failed check as "safe".
 */
public record RiskFactor(String checkName, int score, String reason, boolean available) {

    public RiskFactor {
        if (checkName == null || checkName.isBlank()) {
            throw new IllegalArgumentException("checkName must not be blank");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be between 0 and 100");
        }
        if (!available && score != 0) {
            throw new IllegalArgumentException("an unavailable factor must have score 0");
        }
    }

    /** A check that ran. Score 0 means it ran and found nothing suspicious. */
    public static RiskFactor of(String checkName, int score, String reason) {
        return new RiskFactor(checkName, score, reason, true);
    }

    /** A check that could not run. Contributes nothing to the score. */
    public static RiskFactor unavailable(String checkName, String reason) {
        return new RiskFactor(checkName, 0, reason, false);
    }
}