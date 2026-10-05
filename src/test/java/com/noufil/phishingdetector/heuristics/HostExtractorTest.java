package com.noufil.phishingdetector.heuristics;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class HostExtractorTest {

    @Test
    void plainAsciiHostIsLowerCasedAndStrippedOfPortAndPath() {
        assertEquals(Optional.of("www.example.com"),
                HostExtractor.extractHost("https://www.Example.com:8443/x?y=1#z"));
    }

    @Test
    void urlWithoutSchemeIsTreatedAsHttp() {
        assertEquals(Optional.of("example.com"), HostExtractor.extractHost("example.com/login"));
    }

    @Test
    void trailingDotIsRemoved() {
        assertEquals(Optional.of("example.com"), HostExtractor.extractHost("https://example.com./"));
    }

    @Test
    void ipv4AndIpv6HostsAreReturned() {
        assertEquals(Optional.of("192.168.1.1"), HostExtractor.extractHost("http://192.168.1.1/x"));
        assertEquals(Optional.of("[::1]"), HostExtractor.extractHost("http://[::1]/x"));
    }

    @Test
    void unicodeHostIsConvertedToPunycode() {
        assertEquals(Optional.of("xn--mnchen-3ya.de"), HostExtractor.extractHost("https://m\u00fcnchen.de/path"));
    }

    @Test
    void unicodeHostWithoutSchemeIsConvertedToo() {
        assertEquals(Optional.of("xn--mnchen-3ya.de"), HostExtractor.extractHost("m\u00fcnchen.de"));
    }

    @Test
    void unicodeHostWithUserInfoAndPortIsConverted() {
        assertEquals(Optional.of("xn--mnchen-3ya.de"),
                HostExtractor.extractHost("https://user@m\u00fcnchen.de:8443/x"));
    }

    @Test
    void cyrillicLookalikeHostBecomesPunycodeNotPaypal() {
        Optional<String> host = HostExtractor.extractHost("http://p\u0430ypal.com/login");
        assertEquals(Optional.of("xn--pypal-4ve.com"), host);
        assertFalse(host.get().equals("paypal.com"));
    }

    @Test
    void fullWidthLettersNormaliseToTheirAsciiForm() {
        // Browsers do the same, so the real destination really is google.com.
        assertEquals(Optional.of("google.com"),
                HostExtractor.extractHost("http://\uff47\uff4f\uff4f\uff47\uff4c\uff45.com"));
    }

    @Test
    void fullWidthSlashCannotSmuggleAnotherHost() {
        assertTrue(HostExtractor.extractHost("http://paypal.com\uff0fevil.com").isEmpty());
    }

    @Test
    void overlongLabelIsRejected() {
        assertTrue(HostExtractor.extractHost("http://" + "a".repeat(70) + "\u00fc.com").isEmpty());
    }

    @Test
    void unicodeOnlyInThePathLeavesTheHostAlone() {
        assertEquals(Optional.of("example.com"), HostExtractor.extractHost("https://example.com/caf\u00e9"));
        assertEquals(Optional.of("[::1]"), HostExtractor.extractHost("http://[::1]/caf\u00e9"));
    }

    @Test
    void nonHttpSchemesAreRejectedEvenWithUnicodeHosts() {
        assertTrue(HostExtractor.extractHost("ftp://m\u00fcnchen.de/file").isEmpty());
        assertTrue(HostExtractor.extractHost("javascript:alert(1)").isEmpty());
    }

    @Test
    void emptyAndNullInputGiveEmpty() {
        assertTrue(HostExtractor.extractHost(null).isEmpty());
        assertTrue(HostExtractor.extractHost("").isEmpty());
        assertTrue(HostExtractor.extractHost("http://").isEmpty());
    }

    @Test
    void withAsciiHostLeavesAsciiUrlsUntouched() {
        String url = "http://192.168.1.1/x?q=1";
        assertEquals(url, HostExtractor.withAsciiHost(url));
        assertEquals("no-scheme.example", HostExtractor.withAsciiHost("no-scheme.example"));
    }

    @Test
    void withAsciiHostConvertsOnlyTheHostPart() {
        assertEquals("http://xn--mnchen-3ya.de/x?q=\u00e9",
                HostExtractor.withAsciiHost("http://m\u00fcnchen.de/x?q=\u00e9"));
    }

    @Test
    void withAsciiHostRejectsHostsThatTurnIntoDelimiters() {
        assertThrows(IllegalArgumentException.class,
                () -> HostExtractor.withAsciiHost("http://paypal.com\uff0fevil.com/"));
    }

    @Test
    void registrableLabelCountHandlesTwoPartSuffixes() {
        assertEquals(2, HostExtractor.registrableLabelCount("www.example.com".split("\\.")));
        assertEquals(3, HostExtractor.registrableLabelCount("www.example.co.uk".split("\\.")));
        assertEquals(2, HostExtractor.registrableLabelCount("example.com".split("\\.")));
    }

    @Test
    void ipHostDetection() {
        assertTrue(HostExtractor.isIpHost("192.168.1.1"));
        assertTrue(HostExtractor.isIpHost("[::1]"));
        assertTrue(HostExtractor.isIpHost("3232235777"));
        assertTrue(HostExtractor.isIpHost("0xc0a80101"));
        assertFalse(HostExtractor.isIpHost("example.com"));
    }
}