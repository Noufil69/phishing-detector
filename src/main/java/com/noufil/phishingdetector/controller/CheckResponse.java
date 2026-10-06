package com.noufil.phishingdetector.controller;

import java.util.List;

import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.model.RiskScore;

/**
 * What POST /api/check answers with.
 *
 * It deliberately does NOT contain the submitted URL. The host is the ASCII form that was
 * really checked, so a look-alike address shows up as its "xn--" form instead of passing
 * for the real brand.
 */
public record CheckResponse(
        RiskLevel level,
        int score,
        String summary,
        String host,
        int checksRun,
        int checksTotal,
        String note,
        List<FactorView> factors) {

    /** One line of the per-check breakdown. */
    public record FactorView(String check, int score, String reason, boolean available) {
    }

    /** Fewer than this many checks running means the result is called out as incomplete. */
    static final int FULL_COVERAGE_NOTE_BELOW = 5;

    public static CheckResponse from(RiskScore result, String host) {
        List<FactorView> views = result.factors().stream()
                .map(CheckResponse::view)
                .toList();

        int run = result.checksRun();
        int total = result.checksTotal();

        String summary;
        String note = null;

        if (run == 0) {
            summary = "None of the checks could run, so there is no result. Please try again in a moment.";
        } else {
            summary = summaryFor(result.level());
            if (run < total) {
                note = "Only " + run + " of " + total + " checks could run, so this result is less complete.";
            }
        }

        return new CheckResponse(result.level(), result.totalScore(), summary, host, run, total, note, views);
    }

    private static FactorView view(RiskFactor factor) {
        return new FactorView(factor.checkName(), factor.score(), factor.reason(), factor.available());
    }

    private static String summaryFor(RiskLevel level) {
        return switch (level) {
            case LOW -> "No strong warning signs were found. That does not guarantee the site is safe.";
            case MEDIUM -> "Some warning signs were found. Be careful, and double-check before sharing any personal details.";
            case HIGH -> "Strong warning signs were found. Do not enter passwords, card details or personal information on this site.";
        };
    }
}