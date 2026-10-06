package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.SafeBrowsingClient.NotConfiguredException;
import com.noufil.phishingdetector.model.RiskFactor;

/** All tests use a fake client, so they never touch the internet and need no API key. */
class SafeBrowsingHeuristicTest {

    /** A fake that records every URL it was asked about and answers with a fixed list. */
    private static final class Recorder implements SafeBrowsingClient {
        final List<String> asked = new ArrayList<>();
        private final List<String> answer;

        Recorder(List<String> answer) {
            this.answer = answer;
        }

        @Override
        public List<String> findThreats(String url) {
            asked.add(url);
            return answer;
        }
    }

    private static SafeBrowsingHeuristic with(List<String> answer) {
        return new SafeBrowsingHeuristic(new Recorder(answer));
    }

    @Test
    void nameIsStable() {
        assertEquals("Safe Browsing", with(List.of()).getName());
    }

    @Test
    void notListedScoresZeroButStaysAvailable() {
        RiskFactor f = with(List.of()).evaluate("https://example.com/");
        assertEquals(0, f.score());
        assertTrue(f.available());
        assertTrue(f.reason().contains("Not on Google"));
    }

    @Test
    void phishingListingScoresMaximum() {
        RiskFactor f = with(List.of("SOCIAL_ENGINEERING")).evaluate("https://bad.example/");
        assertEquals(100, f.score());
        assertTrue(f.available());
        assertTrue(f.reason().contains("phishing"));
    }

    @Test
    void malwareListingScoresMaximum() {
        RiskFactor f = with(List.of("MALWARE")).evaluate("https://bad.example/");
        assertEquals(100, f.score());
        assertTrue(f.reason().contains("malware"));
    }

    @Test
    void unwantedSoftwareScoresSlightlyLower() {
        assertEquals(90, with(List.of("UNWANTED_SOFTWARE")).evaluate("https://bad.example/").score());
    }

    @Test
    void otherAndUnknownTypesStillScoreHigh() {
        assertEquals(80, with(List.of("POTENTIALLY_HARMFUL_APPLICATION")).evaluate("https://bad.example/").score());
        assertEquals(80, with(List.of("UNKNOWN")).evaluate("https://bad.example/").score());
    }

    @Test
    void severalTypesUseTheMostSevereOne() {
        RiskFactor f = with(List.of("UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING")).evaluate("https://bad.example/");
        assertEquals(100, f.score());
        assertTrue(f.reason().contains("phishing"));
    }

    @Test
    void missingKeyMakesTheCheckUnavailable() {
        SafeBrowsingHeuristic h = new SafeBrowsingHeuristic(url -> {
            throw new NotConfiguredException();
        });
        RiskFactor f = h.evaluate("https://example.com/");
        assertFalse(f.available());
        assertEquals(0, f.score());
        assertTrue(f.reason().contains("not set up"));
    }

    @Test
    void failuresMakeTheCheckUnavailableAndNeverLookSafe() {
        SafeBrowsingHeuristic h = new SafeBrowsingHeuristic(url -> {
            throw new IOException("boom: key=SECRET-VALUE-123 at https://internal.example/");
        });
        RiskFactor f = h.evaluate("https://example.com/");
        assertFalse(f.available());
        assertEquals(0, f.score());
        assertFalse(f.reason().contains("SECRET-VALUE-123"));
        assertFalse(f.reason().contains("internal.example"));
    }

    @Test
    void urlWithoutSchemeIsSentAsHttp() {
        Recorder r = new Recorder(List.of());
        new SafeBrowsingHeuristic(r).evaluate("example.com/login");
        assertEquals(List.of("http://example.com/login"), r.asked);
    }

    @Test
    void surroundingWhitespaceIsTrimmed() {
        Recorder r = new Recorder(List.of());
        new SafeBrowsingHeuristic(r).evaluate("  https://example.com/a  ");
        assertEquals(List.of("https://example.com/a"), r.asked);
    }

    @Test
    void pathAndQueryAreSentUnchanged() {
        Recorder r = new Recorder(List.of());
        new SafeBrowsingHeuristic(r).evaluate("https://example.com/a/b?x=1&y=2#frag");
        assertEquals(List.of("https://example.com/a/b?x=1&y=2#frag"), r.asked);
    }

    @Test
    void unicodeHostIsSentInItsAsciiForm() {
        Recorder r = new Recorder(List.of());
        new SafeBrowsingHeuristic(r).evaluate("https://m\u00fcnchen.de/path");
        assertEquals(List.of("https://xn--mnchen-3ya.de/path"), r.asked);
    }

    @Test
    void ipAddressUrlsAreStillChecked() {
        Recorder r = new Recorder(List.of());
        RiskFactor f = new SafeBrowsingHeuristic(r).evaluate("http://203.0.113.5/x");
        assertEquals(1, r.asked.size());
        assertTrue(f.available());
    }

    @Test
    void overlongUrlIsNotSent() {
        Recorder r = new Recorder(List.of());
        RiskFactor f = new SafeBrowsingHeuristic(r).evaluate("https://example.com/" + "a".repeat(2100));
        assertFalse(f.available());
        assertTrue(r.asked.isEmpty());
    }

    @Test
    void urlsWithoutAUsableHostAreNotSent() {
        Recorder r = new Recorder(List.of());
        SafeBrowsingHeuristic h = new SafeBrowsingHeuristic(r);
        assertFalse(h.evaluate("").available());
        assertFalse(h.evaluate("   ").available());
        assertFalse(h.evaluate(null).available());
        assertFalse(h.evaluate("ftp://example.com/file").available());
        assertFalse(h.evaluate("javascript:alert(1)").available());
        assertFalse(h.evaluate("http://").available());
        assertTrue(r.asked.isEmpty());
    }

    @Test
    void delimiterSmugglingHostIsNotSent() {
        Recorder r = new Recorder(List.of());
        RiskFactor f = new SafeBrowsingHeuristic(r).evaluate("http://paypal.com\uff0fevil.com/");
        assertFalse(f.available());
        assertTrue(r.asked.isEmpty());
    }
}