package com.noufil.phishingdetector.service;

import com.noufil.phishingdetector.heuristics.HeuristicCheck;
import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskScore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs every registered heuristic against a URL and aggregates the results.
 *
 * <p>One failing check must never take down the others (TRD.md section 4), so each
 * check runs inside a safety net that converts any exception into an
 * "unavailable" factor.
 */
@Service
public class UrlCheckService {

    private static final Logger log = LoggerFactory.getLogger(UrlCheckService.class);

    private final List<HeuristicCheck> checks;
    private final ScoreAggregator aggregator;

    public UrlCheckService(List<HeuristicCheck> checks, ScoreAggregator aggregator) {
        this.checks = List.copyOf(checks);
        this.aggregator = aggregator;
    }

    public RiskScore analyze(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("url must not be blank");
        }
        List<RiskFactor> factors = new ArrayList<>();
        for (HeuristicCheck check : checks) {
            factors.add(runSafely(check, url));
        }
        return aggregator.aggregate(factors);
    }

    private RiskFactor runSafely(HeuristicCheck check, String url) {
        try {
            RiskFactor factor = check.evaluate(url);
            if (factor == null) {
                return RiskFactor.unavailable(check.getName(), "This check returned no result");
            }
            return factor;
        } catch (RuntimeException e) {
            // SECURITY.md: never log the submitted URL. Exception messages can contain
            // it, so log only the check name and the exception type.
            log.warn("Heuristic '{}' failed: {}", check.getName(), e.getClass().getSimpleName());
            return RiskFactor.unavailable(check.getName(), "This check could not be completed");
        }
    }
}