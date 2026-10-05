package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.time.Instant;

/**
 * Connects to a host and reports on the TLS certificate it presents.
 *
 * This is an interface so the SSL heuristic can be unit-tested with a fake,
 * without any real network access.
 */
@FunctionalInterface
public interface TlsInspector {

    /** Only the facts the heuristic needs. Nothing from the certificate text is kept. */
    record CertificateInfo(Instant notBefore, Instant notAfter) {
    }

    /**
     * Performs a TLS handshake with default (strict) certificate validation.
     *
     * @throws IOException for every failure: DNS, connection, timeout, blocked
     *                     address, or an invalid certificate (SSLHandshakeException)
     */
    CertificateInfo inspect(String host) throws IOException;
}