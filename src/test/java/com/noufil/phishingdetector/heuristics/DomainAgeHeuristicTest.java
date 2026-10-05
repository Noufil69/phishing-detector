package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;
import com.noufil.phishingdetector.model.RiskFactor;

/** All tests use a fake RdapClient, so none of them touch the network. */
class DomainAgeHeuristicTest {

    private static DomainAgeHeuristic registeredDaysAgo(long days) {
        return new DomainAgeHeuristic(domain -> Optional.of(Instant.now().minus(days, ChronoUnit.DAYS)));
    }

    private static DomainAgeHeuristic throwing(IOException e) {
        return new DomainAgeHeuristic(domain -> {
            throw e;
        });
    }

    @Test
    void nameIsDomainAge() {
        assertEquals("Domain Age", registeredDaysAgo(10).getName());
    }

    @Test
    void domainRegisteredDaysAgoIsVeryHighRisk() {
        RiskFactor f = registeredDaysAgo(3).evaluate("https://example.com");
        assertEquals(85, f.score());
        assertTrue(f.available());
        assertTrue(f.reason().contains("less than a week"));
    }

    @Test
    void domainUnderAMonthOldIsHighRisk() {
        RiskFactor f = registeredDaysAgo(20).evaluate("https://example.com");
        assertEquals(70, f.score());
        assertTrue(f.reason().contains("20 days"));
    }

    @Test
    void domainUnderThreeMonthsOldIsMediumRisk() {
        assertEquals(45, registeredDaysAgo(60).evaluate("https://example.com").score());
    }

    @Test
    void domainUnderSixMonthsOldIsLowerRisk() {
        assertEquals(25, registeredDaysAgo(120).evaluate("https://example.com").score());
    }

    @Test
    void domainUnderAYearOldIsSlightlyRisky() {
        assertEquals(10, registeredDaysAgo(300).evaluate("https://example.com").score());
    }

    @Test
    void establishedDomainScoresZero() {
        RiskFactor f = registeredDaysAgo(500).evaluate("https://example.com");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void veryOldDomainScoresZeroAndReportsYears() {
        RiskFactor f = registeredDaysAgo(365L * 10).evaluate("https://example.com");
        assertEquals(0, f.score());
        assertTrue(f.reason().contains("years"));
    }

    @Test
    void bucketEdgesBehave() {
        assertEquals(85, registeredDaysAgo(6).evaluate("https://example.com").score());
        assertEquals(70, registeredDaysAgo(8).evaluate("https://example.com").score());
        assertEquals(70, registeredDaysAgo(29).evaluate("https://example.com").score());
        assertEquals(45, registeredDaysAgo(31).evaluate("https://example.com").score());
    }

    @Test
    void registrationDateFarInTheFutureIsUnavailable() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(
                domain -> Optional.of(Instant.now().plus(30, ChronoUnit.DAYS)));
        RiskFactor f = h.evaluate("https://example.com");
        assertFalse(f.available());
        assertEquals(0, f.score());
    }

    @Test
    void registrationDateJustAheadOfOurClockIsTreatedAsBrandNew() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(
                domain -> Optional.of(Instant.now().plus(2, ChronoUnit.HOURS)));
        RiskFactor f = h.evaluate("https://example.com");
        assertTrue(f.available());
        assertEquals(85, f.score());
    }

    @Test
    void registryWithNoDateIsUnavailable() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> Optional.empty());
        RiskFactor f = h.evaluate("https://example.com");
        assertFalse(f.available());
        assertEquals(0, f.score());
    }

    @Test
    void networkFailureIsUnavailable() {
        assertFalse(throwing(new IOException("connection reset")).evaluate("https://example.com").available());
    }

    @Test
    void timeoutIsUnavailable() {
        assertFalse(throwing(new SocketTimeoutException("timed out")).evaluate("https://example.com").available());
    }

    @Test
    void refusedRedirectIsUnavailable() {
        RiskFactor f = throwing(new BlockedAddressException("blocked")).evaluate("https://example.com");
        assertFalse(f.available());
        assertEquals(0, f.score());
    }

    @Test
    void ipAddressHostIsNotLookedUp() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            throw new AssertionError("client must not be called for IP hosts");
        });
        assertFalse(h.evaluate("https://8.8.8.8/login").available());
    }

    @Test
    void malformedUrlIsNotLookedUp() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            throw new AssertionError("client must not be called without a host");
        });
        assertFalse(h.evaluate("http://").available());
    }

    @Test
    void singleLabelHostIsNotLookedUp() {
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            throw new AssertionError("client must not be called for single-label hosts");
        });
        assertFalse(h.evaluate("https://intranet/").available());
    }

    @Test
    void lookupUsesTheRegistrableDomainOnly() {
        String[] seen = new String[1];
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            seen[0] = domain;
            return Optional.of(Instant.now().minus(500, ChronoUnit.DAYS));
        });

        h.evaluate("https://www.login.Example.COM:8443/path?q=1");
        assertEquals("example.com", seen[0]);

        h.evaluate("https://example.com");
        assertEquals("example.com", seen[0]);

        h.evaluate("https://a.b.c.example.net");
        assertEquals("example.net", seen[0]);
    }

    @Test
    void lookupKeepsTwoPartPublicSuffixes() {
        String[] seen = new String[1];
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            seen[0] = domain;
            return Optional.of(Instant.now().minus(500, ChronoUnit.DAYS));
        });

        h.evaluate("https://www.login.example.co.uk/x");
        assertEquals("example.co.uk", seen[0]);

        h.evaluate("https://shop.example.com.pk");
        assertEquals("example.com.pk", seen[0]);
    }

    @Test
    void reasonNeverEchoesExceptionText() {
        RiskFactor f = throwing(new IOException("<script>alert(1)</script> evil-host.example"))
                .evaluate("https://example.com");
        assertFalse(f.reason().contains("script"));
        assertFalse(f.reason().contains("evil-host"));
    }
}