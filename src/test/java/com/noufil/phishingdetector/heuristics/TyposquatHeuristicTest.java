package com.noufil.phishingdetector.heuristics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.model.RiskFactor;

class TyposquatHeuristicTest {

    private final TyposquatHeuristic heuristic = new TyposquatHeuristic();

    @Test
    void nameIsTyposquat() {
        assertEquals("Typosquat", heuristic.getName());
    }

    @Test
    void genuineBrandDomainScoresZero() {
        RiskFactor f = heuristic.evaluate("https://www.paypal.com/signin");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void genuineBrandWithCountryTldScoresZero() {
        assertEquals(0, heuristic.evaluate("https://www.paypal.com.pk").score());
    }

    @Test
    void brandSubdomainOnGenuineDomainScoresZero() {
        assertEquals(0, heuristic.evaluate("https://mail.google.com").score());
    }

    @Test
    void unrelatedDomainScoresZero() {
        assertEquals(0, heuristic.evaluate("https://example.com").score());
    }

    @Test
    void digitOneForLetterLIsCaught() {
        RiskFactor f = heuristic.evaluate("https://paypa1.com/login");
        assertEquals(90, f.score());
        assertTrue(f.reason().contains("paypal"));
    }

    @Test
    void zerosForOsAreCaught() {
        assertEquals(90, heuristic.evaluate("https://g00gle.com").score());
    }

    @Test
    void rnForMIsCaught() {
        assertEquals(90, heuristic.evaluate("https://rnicrosoft.com").score());
    }

    @Test
    void urlWithoutSchemeIsStillChecked() {
        assertEquals(90, heuristic.evaluate("paypa1.com/login").score());
    }

    @Test
    void extraLetterIsOneEditAway() {
        RiskFactor f = heuristic.evaluate("https://paypall.com");
        assertEquals(70, f.score());
        assertTrue(f.reason().contains("paypal"));
    }

    @Test
    void missingLetterIsOneEditAway() {
        assertEquals(70, heuristic.evaluate("https://gogle.com").score());
    }

    @Test
    void swappedLettersInLongBrandAreTwoEditsAway() {
        assertEquals(40, heuristic.evaluate("https://microsfot.com").score());
    }

    @Test
    void shortBrandsAreNotMatchedByEditDistance() {
        // "eba" is one edit from "ebay" but ebay is too short to judge by distance
        assertEquals(0, heuristic.evaluate("https://eba.com").score());
    }

    @Test
    void brandInSubdomainOfOtherDomainIsFlagged() {
        RiskFactor f = heuristic.evaluate("https://paypal.com.evil-site.net");
        assertEquals(50, f.score());
        assertTrue(f.reason().contains("subdomain"));
    }

    @Test
    void brandInsideHyphenatedNameIsFlagged() {
        RiskFactor f = heuristic.evaluate("https://paypal-secure-login.com");
        assertEquals(50, f.score());
        assertTrue(f.reason().contains("paypal"));
    }

    @Test
    void ipHostIsNotApplicable() {
        RiskFactor f = heuristic.evaluate("https://192.168.1.1/login");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void malformedUrlDoesNotThrow() {
        RiskFactor f = heuristic.evaluate("http://");
        assertEquals(0, f.score());
        assertTrue(f.available());
    }

    @Test
    void levenshteinBasics() {
        assertEquals(0, TyposquatHeuristic.levenshtein("paypal", "paypal"));
        assertEquals(3, TyposquatHeuristic.levenshtein("kitten", "sitting"));
        assertEquals(3, TyposquatHeuristic.levenshtein("", "abc"));
        assertEquals(3, TyposquatHeuristic.levenshtein("abc", ""));
        assertEquals(1, TyposquatHeuristic.levenshtein("paypal", "paypall"));
    }
}