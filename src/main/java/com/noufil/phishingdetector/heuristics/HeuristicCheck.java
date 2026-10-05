package com.noufil.phishingdetector.heuristics;

import com.noufil.phishingdetector.model.RiskFactor;

/**
 * One independent way of judging a URL (Strategy pattern).
 *
 * <p>Each implementation is a Spring bean. UrlCheckService runs every bean it
 * finds, so adding a new heuristic means adding one class and nothing else.
 */
public interface HeuristicCheck {

    /** Short human-readable name, e.g. "Domain age". Shown in the results breakdown. */
    String getName();

    /**
     * Judge the URL. Implementations should return {@link RiskFactor#unavailable}
     * when they cannot run (timeout, lookup failure) rather than throwing, but
     * the service also guards against exceptions as a safety net.
     */
    RiskFactor evaluate(String url);
}