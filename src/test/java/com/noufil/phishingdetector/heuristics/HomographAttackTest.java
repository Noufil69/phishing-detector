package com.noufil.phishingdetector.heuristics;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Look-alike (homograph) domains: addresses that use letters from other alphabets
 * or accents to imitate a real brand. Special characters are written as unicode
 * escapes in this file, so the source stays plain ASCII and every character is visible.
 *
 *  U+0430 = Cyrillic a      U+043E = Cyrillic o      U+0440 = Cyrillic p
 *  U+03BF = Greek omicron   U+00E1 = a with accent   U+00FC = u with umlaut
 *  U+FF0F = full-width slash
 */
class HomographAttackTest {

    private final TyposquatHeuristic typosquat = new TyposquatHeuristic();
    private final StructuralHeuristic structural = new StructuralHeuristic();

    // ---------- Confusables ----------

    @Test
    void skeletonTurnsLookalikesIntoPlainLetters() {
        assertEquals("paypal", Confusables.skeleton("p\u0430ypal"));
        assertEquals("paypal", Confusables.skeleton("\u0440\u0430ypal"));
        assertEquals("google", Confusables.skeleton("g\u043e\u043egle"));
        assertEquals("openai", Confusables.skeleton("\u03bfpenai"));
        assertEquals("paypal", Confusables.skeleton("payp\u00e1l"));
        assertEquals("munchen", Confusables.skeleton("m\u00fcnchen"));
        assertEquals("paypal", Confusables.skeleton("PAYPAL"));
        assertEquals("ae", Confusables.skeleton("\u00e6"));
        assertEquals("", Confusables.skeleton(""));
    }

    @Test
    void comparableLeavesPlainLabelsAlone() {
        assertEquals("example", Confusables.comparable("example"));
        assertEquals("paypal", Confusables.comparable("paypal"));
    }

    @Test
    void comparableDecodesPunycodeLabels() {
        assertEquals("paypal", Confusables.comparable("xn--pypal-4ve"));
        assertEquals("munchen", Confusables.comparable("xn--mnchen-3ya"));
    }

    @Test
    void comparableSurvivesBrokenPunycode() {
        // Must not throw. The exact text returned is not important.
        assertTrue(Confusables.comparable("xn--zzzz-not-valid-punycode") != null);
        assertTrue(Confusables.comparable("xn--") != null);
    }

    // ---------- Typosquat ----------

    @Test
    void cyrillicAInPaypalIsCaught() {
        RiskFactor f = typosquat.evaluate("http://p\u0430ypal.com/login");
        assertEquals(90, f.score());
        assertTrue(f.reason().contains("paypal"));
        assertTrue(f.available());
    }

    @Test
    void severalCyrillicLettersInPaypalAreCaught() {
        assertEquals(90, typosquat.evaluate("https://\u0440\u0430ypal.com").score());
    }

    @Test
    void accentedLetterInPaypalIsCaught() {
        assertEquals(90, typosquat.evaluate("https://payp\u00e1l.com").score());
    }

    @Test
    void cyrillicOsInGoogleAreCaughtEvenBehindASubdomain() {
        assertEquals(90, typosquat.evaluate("https://www.g\u043e\u043egle.com").score());
    }

    @Test
    void greekOmicronInOpenaiIsCaught() {
        assertEquals(90, typosquat.evaluate("https://\u03bfpenai.com").score());
    }

    @Test
    void lookalikeCombinedWithATypoIsStillCaught() {
        // paypall with a Cyrillic a: one edit away after the look-alike is undone
        assertEquals(70, typosquat.evaluate("https://p\u0430ypall.com").score());
    }

    @Test
    void lookalikeBrandInSubdomainIsCaught() {
        RiskFactor f = typosquat.evaluate("http://p\u0430ypal.com.evil-site.net");
        assertEquals(50, f.score());
        assertTrue(f.reason().contains("subdomain"));
    }

    @Test
    void genuineInternationalDomainIsNotFlagged() {
        assertEquals(0, typosquat.evaluate("https://m\u00fcnchen.de").score());
    }

    @Test
    void genuineBrandIsStillClean() {
        assertEquals(0, typosquat.evaluate("https://www.paypal.com").score());
    }

    @Test
    void fullWidthLettersThatReallyMeanGoogleAreNotFlaggedAsAttack() {
        // Browsers turn these into google.com, so the destination really is google.com.
        assertEquals(0, typosquat.evaluate("http://\uff47\uff4f\uff4f\uff47\uff4c\uff45.com").score());
    }

    // ---------- Structural ----------

    @Test
    void structuralCheckFlagsPunycodeLookalikeInsteadOfCallingItMalformed() {
        RiskFactor f = structural.evaluate("https://p\u0430ypal.com/login");
        assertEquals(20, f.score());
        assertTrue(f.reason().contains("punycode"));
    }

    @Test
    void structuralCheckAddsHttpPenaltyForLookalikeOverPlainHttp() {
        assertEquals(30, structural.evaluate("http://p\u0430ypal.com/login").score());
    }

    @Test
    void structuralCheckFlagsUnicodeUserInfoTrick() {
        // '@' (30) + punycode host (20)
        assertEquals(50, structural.evaluate("https://user@m\u00fcnchen.de:8443/x").score());
    }

    @Test
    void structuralCheckTreatsDelimiterSmugglingAsMalformed() {
        RiskFactor f = structural.evaluate("http://paypal.com\uff0fevil.com");
        assertEquals(30, f.score());
        assertTrue(f.reason().contains("malformed"));
    }

    // ---------- Network checks receive the ASCII form ----------

    @Test
    void domainAgeLooksUpThePunycodeDomain() {
        String[] seen = new String[1];
        DomainAgeHeuristic h = new DomainAgeHeuristic(domain -> {
            seen[0] = domain;
            return Optional.of(Instant.now().minus(500, ChronoUnit.DAYS));
        });
        h.evaluate("https://www.m\u00fcnchen.de/x");
        assertEquals("xn--mnchen-3ya.de", seen[0]);
    }

    @Test
    void sslCheckConnectsToThePunycodeHost() {
        String[] seen = new String[1];
        SslCertificateHeuristic h = new SslCertificateHeuristic(host -> {
            seen[0] = host;
            Instant now = Instant.now();
            return new TlsInspector.CertificateInfo(now.minus(90, ChronoUnit.DAYS), now.plus(200, ChronoUnit.DAYS));
        });
        h.evaluate("https://m\u00fcnchen.de/path");
        assertEquals("xn--mnchen-3ya.de", seen[0]);
    }
}