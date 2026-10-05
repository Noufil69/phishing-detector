package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * Looks up when a domain was first registered.
 *
 * An interface so the domain-age heuristic can be unit-tested with a fake,
 * without any real network access.
 */
@FunctionalInterface
public interface RdapClient {

    /**
     * @param domain the registrable domain, for example "example.com" or "example.co.uk"
     * @return the registration date, or empty if the registry has no record or
     *         does not publish one
     * @throws IOException for every failure: network, timeout, bad response, or a
     *                     redirect that was refused for safety reasons
     */
    Optional<Instant> fetchRegistrationDate(String domain) throws IOException;
}