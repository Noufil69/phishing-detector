package com.noufil.phishingdetector.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class UrlInputValidatorTest {

    // ---------- accepted ----------

    @Test
    void aNormalUrlIsAccepted() {
        assertEquals("https://example.com/login?x=1", UrlInputValidator.validate("https://example.com/login?x=1"));
    }

    @Test
    void surroundingWhitespaceIsTrimmed() {
        assertEquals("https://example.com", UrlInputValidator.validate("  https://example.com \n"));
    }

    @Test
    void aBareDomainIsAccepted() {
        assertEquals("example.com/login", UrlInputValidator.validate("example.com/login"));
    }

    @Test
    void ipAddressesAreAcceptedBecauseTheChecksFlagThemInstead() {
        assertEquals("http://203.0.113.5/x", UrlInputValidator.validate("http://203.0.113.5/x"));
        assertEquals("http://[::1]/x", UrlInputValidator.validate("http://[::1]/x"));
    }

    @Test
    void unicodeDomainsAreAccepted() {
        assertEquals("https://m\u00fcnchen.de", UrlInputValidator.validate("https://m\u00fcnchen.de"));
    }

    @Test
    void aUrlOfExactlyTheMaximumLengthIsAccepted() {
        String url = "https://example.com/" + "a".repeat(UrlInputValidator.MAX_LENGTH - "https://example.com/".length());
        assertEquals(UrlInputValidator.MAX_LENGTH, url.length());
        assertEquals(url, UrlInputValidator.validate(url));
    }

    // ---------- rejected ----------

    @Test
    void emptyInputIsRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate(null));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate(""));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("    "));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("\n\t"));
    }

    @Test
    void tooLongInputIsRejected() {
        String url = "https://example.com/" + "a".repeat(UrlInputValidator.MAX_LENGTH);
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate(url));
    }

    @Test
    void spacesAndControlCharactersInsideAreRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("https://exa mple.com"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("https://example.com/a\tb"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("https://example.com/\nHost: evil"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("https://exam\u0000ple.com/"));
    }

    @Test
    void otherSchemesAreRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("ftp://example.com/file"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("javascript:alert(1)"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("mailto:a@example.com"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("file:///etc/passwd"));
    }

    @Test
    void aPortIsAcceptedWithOrWithoutAScheme() {
        assertEquals("example.com:8080/x", UrlInputValidator.validate("example.com:8080/x"));
        assertEquals("https://example.com:8443/x", UrlInputValidator.validate("https://example.com:8443/x"));
        assertEquals("[::1]:8080/x", UrlInputValidator.validate("[::1]:8080/x"));
    }

    @Test
    void textThatOnlyLooksLikeAnAddressIsRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("user@example.com"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("user:pw@example.com"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("http:/example.com"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("example.com:abc/x"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("tel:+123456"));
    }

    @Test
    void hostsWithoutADotAreRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("localhost"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("http://intranet/admin"));
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("http://"));
    }

    @Test
    void delimiterSmugglingIsRejected() {
        assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate("http://paypal.com\uff0fevil.com/"));
    }

    @Test
    void messagesNeverEchoTheSubmittedText() {
        String[] inputs = {
                "ftp://secret-host-123.example/file",
                "http://secret-host-123",
                "https://secret-host-123.example/a b",
                "secret-host-123"
        };
        for (String input : inputs) {
            InvalidUrlException e = assertThrows(InvalidUrlException.class, () -> UrlInputValidator.validate(input));
            assertFalse(e.getMessage().contains("secret-host-123"), input);
        }
    }
}