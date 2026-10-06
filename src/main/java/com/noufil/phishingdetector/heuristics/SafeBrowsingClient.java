package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.util.List;

/**
 * Asks Google Safe Browsing whether a URL is on one of its threat lists.
 *
 * An interface so the heuristic can be unit-tested with a fake, without any
 * network access and without an API key.
 */
@FunctionalInterface
public interface SafeBrowsingClient {

    /**
     * @param url an http or https URL with an ASCII host
     * @return the threat types Google lists the URL under, for example
     *         "SOCIAL_ENGINEERING" or "MALWARE". Empty means "not on any list".
     * @throws NotConfiguredException if no API key has been set up
     * @throws IOException            for every other failure: network, timeout, quota,
     *                                bad key, or an answer that cannot be understood.
     *                                A failed lookup is never reported as "no threats".
     */
    List<String> findThreats(String url) throws IOException;

    /** Thrown when the API key is missing, so the check can say "not configured". */
    class NotConfiguredException extends IOException {
        public NotConfiguredException() {
            super("Safe Browsing is not configured");
        }
    }
}