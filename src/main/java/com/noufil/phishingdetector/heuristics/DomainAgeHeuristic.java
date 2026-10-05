package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Optional;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;
import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Heuristic 4: domain age.
 *
 * Newly registered domains are a classic phishing signal: attackers register a
 * domain, use it for a few days, and abandon it. The younger the domain, the
 * higher the score.
 *
 * Uses RDAP through an RdapClient. Where a registry offers no RDAP service or
 * publishes no registration date, the check reports "unavailable" and is left out
 * of the final score instead of guessing.
 */
@Component
public class DomainAgeHeuristic implements HeuristicCheck {

    static final String NAME = "Domain Age";

    static final int POINTS_UNDER_1_WEEK = 85;
    static final int POINTS_UNDER_1_MONTH = 70;
    static final int POINTS_UNDER_3_MONTHS = 45;
    static final int POINTS_UNDER_6_MONTHS = 25;
    static final int POINTS_UNDER_1_YEAR = 10;

    private final RdapClient rdapClient;

    public DomainAgeHeuristic(RdapClient rdapClient) {
        this.rdapClient = rdapClient;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public RiskFactor evaluate(String url) {
        Optional<String> hostOpt = HostExtractor.extractHost(url);
        if (hostOpt.isEmpty()) {
            return RiskFactor.unavailable(NAME, "No valid host name to check");
        }
        String host = hostOpt.get();

        if (HostExtractor.isIpHost(host)) {
            return RiskFactor.unavailable(NAME, "Domain age does not apply to IP address hosts");
        }

        String[] labels = host.split("\\.");
        if (labels.length < 2) {
            return RiskFactor.unavailable(NAME, "Not a registrable domain name");
        }

        int count = Math.min(HostExtractor.registrableLabelCount(labels), labels.length);
        String domain = String.join(".", Arrays.copyOfRange(labels, labels.length - count, labels.length));

        try {
            Optional<Instant> registered = rdapClient.fetchRegistrationDate(domain);
            if (registered.isEmpty()) {
                return RiskFactor.unavailable(NAME,
                        "The registry does not publish a registration date for this domain");
            }
            return assess(registered.get());
        } catch (BlockedAddressException e) {
            return RiskFactor.unavailable(NAME, "Lookup skipped for safety reasons");
        } catch (IOException e) {
            return RiskFactor.unavailable(NAME, "Could not look up registration data for this domain");
        }
    }

    private RiskFactor assess(Instant registered) {
        Instant now = Instant.now();

        // A registration date well in the future means bad data. Don't guess.
        if (registered.isAfter(now.plus(1, ChronoUnit.DAYS))) {
            return RiskFactor.unavailable(NAME, "The registration date looks unreliable");
        }

        long days = Math.max(0, Duration.between(registered, now).toDays());
        int score = scoreForAge(days);
        return RiskFactor.of(NAME, score, "The domain was registered " + describeAge(days));
    }

    private int scoreForAge(long days) {
        if (days < 7) {
            return POINTS_UNDER_1_WEEK;
        }
        if (days < 30) {
            return POINTS_UNDER_1_MONTH;
        }
        if (days < 90) {
            return POINTS_UNDER_3_MONTHS;
        }
        if (days < 180) {
            return POINTS_UNDER_6_MONTHS;
        }
        if (days < 365) {
            return POINTS_UNDER_1_YEAR;
        }
        return 0;
    }

    private String describeAge(long days) {
        if (days < 7) {
            return "less than a week ago";
        }
        if (days < 60) {
            return days + " days ago";
        }
        if (days < 730) {
            return "about " + (days / 30) + " months ago";
        }
        return "about " + (days / 365) + " years ago";
    }
}