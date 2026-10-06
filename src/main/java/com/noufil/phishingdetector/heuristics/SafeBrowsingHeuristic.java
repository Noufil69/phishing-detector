package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.heuristics.SafeBrowsingClient.NotConfiguredException;
import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Heuristic 5: Google Safe Browsing.
 *
 * Google keeps lists of known phishing, malware and unwanted-software URLs.
 * A match is the strongest signal this app has, because it is a known bad site
 * and not a guess. No match proves nothing, though: a brand-new phishing page
 * is often not listed yet, so "not listed" scores 0 and says so.
 *
 * Where no API key is set, or Google cannot be reached, the check reports
 * "unavailable" and is left out of the final score.
 */
@Component
public class SafeBrowsingHeuristic implements HeuristicCheck {

    static final String NAME = "Safe Browsing";

    static final int POINTS_PHISHING = 100;
    static final int POINTS_MALWARE = 100;
    static final int POINTS_UNWANTED = 90;
    static final int POINTS_OTHER = 80;

    static final int MAX_URL_LENGTH = 2048;

    private final SafeBrowsingClient client;

    public SafeBrowsingHeuristic(SafeBrowsingClient client) {
        this.client = client;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public RiskFactor evaluate(String url) {
        if (url == null || url.isBlank()) {
            return RiskFactor.unavailable(NAME, "No URL to check");
        }

        String trimmed = url.trim();
        if (trimmed.length() > MAX_URL_LENGTH) {
            return RiskFactor.unavailable(NAME, "The URL is too long to check");
        }

        Optional<String> host = HostExtractor.extractHost(trimmed);
        if (host.isEmpty()) {
            return RiskFactor.unavailable(NAME, "No valid host name to check");
        }

        String withScheme = trimmed.contains("://") ? trimmed : "http://" + trimmed;
        String asciiUrl;
        try {
            asciiUrl = HostExtractor.withAsciiHost(withScheme);
        } catch (IllegalArgumentException e) {
            return RiskFactor.unavailable(NAME, "No valid host name to check");
        }

        try {
            return assess(client.findThreats(asciiUrl));
        } catch (NotConfiguredException e) {
            return RiskFactor.unavailable(NAME, "Safe Browsing is not set up on this server");
        } catch (IOException e) {
            return RiskFactor.unavailable(NAME, "Could not get an answer from Google Safe Browsing");
        }
    }

    private RiskFactor assess(List<String> threats) {
        if (threats.isEmpty()) {
            return RiskFactor.of(NAME, 0,
                    "Not on Google's Safe Browsing lists (new threats may not be listed yet)");
        }

        int score = 0;
        String reason = null;
        for (String threat : threats) {
            int points;
            String text;
            switch (threat) {
                case "SOCIAL_ENGINEERING" -> {
                    points = POINTS_PHISHING;
                    text = "Google Safe Browsing lists this URL as a phishing or deceptive site";
                }
                case "MALWARE" -> {
                    points = POINTS_MALWARE;
                    text = "Google Safe Browsing lists this URL as a malware site";
                }
                case "UNWANTED_SOFTWARE" -> {
                    points = POINTS_UNWANTED;
                    text = "Google Safe Browsing lists this URL as distributing unwanted software";
                }
                default -> {
                    points = POINTS_OTHER;
                    text = "Google Safe Browsing lists this URL as harmful";
                }
            }
            if (points > score) {
                score = points;
                reason = text;
            }
        }
        return RiskFactor.of(NAME, score, reason);
    }
}