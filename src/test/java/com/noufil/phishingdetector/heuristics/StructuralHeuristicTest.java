package com.noufil.phishingdetector.heuristics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.model.RiskFactor;

class StructuralHeuristicTest {

    private final StructuralHeuristic heuristic = new StructuralHeuristic();

    @Test
    void nameIsStructural() {
        assertEquals("Structural", heuristic.getName());
    }

    @Test
    void cleanHttpsUrlScoresZero() {
        RiskFactor f = heuristic.evaluate("https://www.google.com/search?q=cats");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void urlWithoutSchemeIsNotPenalised() {
        assertEquals(0, heuristic.evaluate("google.com").score());
    }

    @Test
    void explicitPlainHttpGetsSmallPenalty() {
        assertEquals(10, heuristic.evaluate("http://www.example.com").score());
    }

    @Test
    void ipAddressHostIsFlagged() {
        RiskFactor f = heuristic.evaluate("https://192.168.1.1/login");
        assertEquals(40, f.score());
        assertTrue(f.reason().contains("IP address"));
    }

    @Test
    void numericHostIsTreatedAsIp() {
        assertEquals(40, heuristic.evaluate("https://3232235777/login").score());
    }

    @Test
    void ipv6HostIsTreatedAsIp() {
        assertEquals(40, heuristic.evaluate("https://[2001:db8::1]/login").score());
    }

    @Test
    void atSignDisguisingHostIsFlagged() {
        RiskFactor f = heuristic.evaluate("https://paypal.com@evil.xyz/login");
        // 30 for '@' + 20 for .xyz
        assertEquals(50, f.score());
        assertTrue(f.reason().contains("@"));
    }

    @Test
    void shortenerIsFlagged() {
        assertEquals(25, heuristic.evaluate("https://bit.ly/abc123").score());
    }

    @Test
    void suspiciousTldIsFlagged() {
        RiskFactor f = heuristic.evaluate("https://free-prize.xyz");
        assertEquals(20, f.score());
        assertTrue(f.reason().contains(".xyz"));
    }

    @Test
    void deepSubdomainsAreFlagged() {
        RiskFactor f = heuristic.evaluate("https://secure.login.account.paypal.com.example.net");
        assertEquals(25, f.score());
    }

    @Test
    void twoSubdomainLevelsGetSmallerPenalty() {
        assertEquals(10, heuristic.evaluate("https://a.b.example.com").score());
    }

    @Test
    void multiPartTldIsNotCountedAsSubdomain() {
        // www.bbc.co.uk: registrable domain is bbc.co.uk, so only 1 subdomain
        assertEquals(0, heuristic.evaluate("https://www.bbc.co.uk").score());
    }

    @Test
    void punycodeLabelIsFlagged() {
        assertEquals(20, heuristic.evaluate("https://xn--pple-43d.com").score());
    }

    @Test
    void manyHyphensAreFlagged() {
        assertEquals(10, heuristic.evaluate("https://secure-login-update-account.com").score());
    }

    @Test
    void veryLongUrlIsFlagged() {
        String longUrl = "https://example.com/" + "a".repeat(120);
        assertEquals(10, heuristic.evaluate(longUrl).score());
    }

    @Test
    void javascriptSchemeIsHighRisk() {
        assertEquals(60, heuristic.evaluate("javascript:alert(1)").score());
    }

    @Test
    void ftpSchemeIsHighRisk() {
        assertEquals(60, heuristic.evaluate("ftp://example.com/file").score());
    }

    @Test
    void malformedUrlIsFlaggedNotThrown() {
        RiskFactor f = heuristic.evaluate("http://");
        assertEquals(30, f.score());
        assertTrue(f.available());
    }

    @Test
    void scoreNeverExceedsHundred() {
        String nasty = "http://user@xn--a.b.c.d.e.f.secure-login-update.xyz/" + "a".repeat(120);
        RiskFactor f = heuristic.evaluate(nasty);
        assertTrue(f.score() <= 100);
        assertTrue(f.score() > 60);
    }
}