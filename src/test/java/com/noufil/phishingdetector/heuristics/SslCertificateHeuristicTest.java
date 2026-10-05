package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;
import com.noufil.phishingdetector.heuristics.TlsInspector.CertificateInfo;
import com.noufil.phishingdetector.model.RiskFactor;

/** All tests use a fake TlsInspector, so none of them touch the network. */
class SslCertificateHeuristicTest {

    private static CertificateInfo certificate(long issuedDaysAgo, long expiresInDays) {
        Instant now = Instant.now();
        return new CertificateInfo(
                now.minus(issuedDaysAgo, ChronoUnit.DAYS),
                now.plus(expiresInDays, ChronoUnit.DAYS));
    }

    private static SslCertificateHeuristic returning(CertificateInfo info) {
        return new SslCertificateHeuristic(host -> info);
    }

    private static SslCertificateHeuristic throwing(IOException e) {
        return new SslCertificateHeuristic(host -> {
            throw e;
        });
    }

    @Test
    void nameIsSslCertificate() {
        assertEquals("SSL Certificate", returning(certificate(90, 200)).getName());
    }

    @Test
    void establishedValidCertificateScoresZero() {
        RiskFactor f = returning(certificate(90, 200)).evaluate("https://example.com");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void veryNewCertificateGetsSmallPenalty() {
        assertEquals(15, returning(certificate(1, 89)).evaluate("https://example.com").score());
    }

    @Test
    void certificateExpiringSoonGetsSmallPenalty() {
        assertEquals(10, returning(certificate(80, 3)).evaluate("https://example.com").score());
    }

    @Test
    void newAndExpiringSoonAddsBothPenalties() {
        assertEquals(25, returning(certificate(1, 3)).evaluate("https://example.com").score());
    }

    @Test
    void expiredDatesAreCaughtEvenIfHandshakeSucceeded() {
        RiskFactor f = returning(certificate(100, -5)).evaluate("https://example.com");
        assertEquals(70, f.score());
        assertTrue(f.reason().contains("expired"));
    }

    @Test
    void notYetValidDatesAreCaughtEvenIfHandshakeSucceeded() {
        assertEquals(70, returning(certificate(-3, 90)).evaluate("https://example.com").score());
    }

    @Test
    void expiredCertificateIsHighRisk() {
        SSLHandshakeException e = new SSLHandshakeException("PKIX path validation failed");
        e.initCause(new CertificateExpiredException("NotAfter: some date"));

        RiskFactor f = throwing(e).evaluate("https://example.com");
        assertEquals(70, f.score());
        assertTrue(f.reason().contains("expired"));
        assertTrue(f.available());
    }

    @Test
    void notYetValidCertificateIsHighRisk() {
        SSLHandshakeException e = new SSLHandshakeException("PKIX path validation failed");
        e.initCause(new CertificateNotYetValidException("NotBefore: some date"));

        assertEquals(70, throwing(e).evaluate("https://example.com").score());
    }

    @Test
    void hostNameMismatchIsHighestRisk() {
        SSLHandshakeException e = new SSLHandshakeException(
                "No subject alternative DNS name matching example.com found.");

        RiskFactor f = throwing(e).evaluate("https://example.com");
        assertEquals(80, f.score());
        assertTrue(f.reason().contains("does not match"));
    }

    @Test
    void untrustedIssuerIsHighRisk() {
        SSLHandshakeException e = new SSLHandshakeException(
                "PKIX path building failed: unable to find valid certification path to requested target");

        RiskFactor f = throwing(e).evaluate("https://example.com");
        assertEquals(75, f.score());
        assertTrue(f.reason().contains("not trusted"));
    }

    @Test
    void untrustedMessageInsideCauseIsStillRecognised() {
        SSLHandshakeException e = new SSLHandshakeException("handshake_failure");
        e.initCause(new IOException("PKIX path building failed"));

        assertEquals(75, throwing(e).evaluate("https://example.com").score());
    }

    @Test
    void unknownHandshakeFailureIsStillHighRisk() {
        SSLHandshakeException e = new SSLHandshakeException("Received fatal alert: handshake_failure");
        assertEquals(70, throwing(e).evaluate("https://example.com").score());
    }

    @Test
    void otherTlsErrorIsMediumRisk() {
        assertEquals(50, throwing(new SSLException("Unsupported or unrecognized SSL message"))
                .evaluate("https://example.com").score());
    }

    @Test
    void connectionRefusedMeansNoHttps() {
        RiskFactor f = throwing(new ConnectException("Connection refused"))
                .evaluate("http://example.com");
        assertEquals(30, f.score());
        assertTrue(f.available());
    }

    @Test
    void connectTimeoutIsUnavailableNotRisky() {
        RiskFactor f = throwing(new SocketTimeoutException("Connect timed out"))
                .evaluate("https://example.com");
        assertFalse(f.available());
        assertEquals(0, f.score());
    }

    @Test
    void osLevelConnectTimeoutIsAlsoUnavailable() {
        RiskFactor f = throwing(new ConnectException("Connection timed out: connect"))
                .evaluate("https://example.com");
        assertFalse(f.available());
    }

    @Test
    void unresolvableDomainIsUnavailable() {
        RiskFactor f = throwing(new UnknownHostException("example.com"))
                .evaluate("https://example.com");
        assertFalse(f.available());
    }

    @Test
    void blockedInternalAddressIsUnavailable() {
        RiskFactor f = throwing(new BlockedAddressException("blocked"))
                .evaluate("https://internal.example.com");
        assertFalse(f.available());
        assertEquals(0, f.score());
    }

    @Test
    void otherNetworkErrorIsUnavailable() {
        assertFalse(throwing(new SocketException("Network is unreachable"))
                .evaluate("https://example.com").available());
    }

    @Test
    void ipAddressHostIsNotCheckedAndNeverReachesTheInspector() {
        SslCertificateHeuristic h = new SslCertificateHeuristic(host -> {
            throw new AssertionError("inspector must not be called for IP hosts");
        });
        RiskFactor f = h.evaluate("https://8.8.8.8/login");
        assertFalse(f.available());
    }

    @Test
    void malformedUrlIsUnavailableAndNeverReachesTheInspector() {
        SslCertificateHeuristic h = new SslCertificateHeuristic(host -> {
            throw new AssertionError("inspector must not be called without a host");
        });
        assertFalse(h.evaluate("http://").available());
    }

    @Test
    void inspectorReceivesCleanLowerCaseHostOnly() {
        String[] seen = new String[1];
        SslCertificateHeuristic h = new SslCertificateHeuristic(host -> {
            seen[0] = host;
            return certificate(90, 200);
        });
        h.evaluate("https://WWW.Example.COM:8443/some/path?q=1");
        assertEquals("www.example.com", seen[0]);
    }

    @Test
    void reasonNeverEchoesExceptionText() {
        SSLHandshakeException e = new SSLHandshakeException("<script>alert(1)</script> evil-host.example");
        RiskFactor f = throwing(e).evaluate("https://example.com");
        assertFalse(f.reason().contains("script"));
        assertFalse(f.reason().contains("evil-host"));
    }
}