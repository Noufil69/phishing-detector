package com.noufil.phishingdetector.heuristics;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Small shared helper that pulls the host name out of a user-pasted URL.
 *
 * Pure string work. It never makes a network call.
 *
 * Host names written with non-English letters (for example a Cyrillic letter a, U+0430,
 * inside a fake "paypal.com") are converted to their ASCII "xn--" form, the same way a
 * browser does it. That keeps every later check working on plain ASCII and makes
 * look-alike domains visible instead of making them unparseable.
 */
public final class HostExtractor {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern NUMERIC_HOST = Pattern.compile("^(0x[0-9a-f]+|\\d+)$");
    private static final Pattern SAFE_ASCII_HOST = Pattern.compile("^[A-Za-z0-9.-]+$");

    // Second-level labels that act like part of the public suffix (co.uk, com.pk, ...).
    private static final Set<String> SECOND_LEVEL_LABELS = Set.of(
            "co", "com", "org", "net", "gov", "edu", "ac");

    private HostExtractor() {
    }

    /**
     * Returns the lower-case ASCII host, or empty if the URL has no usable http(s) host.
     * A URL without a scheme (for example "paypa1.com/login") is treated as http.
     */
    public static Optional<String> extractHost(String url) {
        if (url == null) {
            return Optional.empty();
        }
        String trimmed = url.trim();
        String normalized = trimmed.contains("://") ? trimmed : "http://" + trimmed;

        try {
            normalized = withAsciiHost(normalized);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }

        URI uri;
        try {
            uri = new URI(normalized);
        } catch (URISyntaxException e) {
            return Optional.empty();
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return Optional.empty();
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }

    /**
     * Takes a URL that already has a scheme ("http://...") and, if its host contains
     * non-ASCII characters, returns the same URL with the host converted to ASCII
     * (punycode). URLs whose authority is already plain ASCII are returned unchanged.
     *
     * @throws IllegalArgumentException if the host cannot be converted safely
     */
    public static String withAsciiHost(String urlWithScheme) {
        int schemeEnd = urlWithScheme.indexOf("://");
        if (schemeEnd < 0) {
            return urlWithScheme;
        }

        int authorityStart = schemeEnd + 3;
        int authorityEnd = authorityStart;
        while (authorityEnd < urlWithScheme.length() && "/?#".indexOf(urlWithScheme.charAt(authorityEnd)) < 0) {
            authorityEnd++;
        }

        String authority = urlWithScheme.substring(authorityStart, authorityEnd);
        if (isAscii(authority)) {
            return urlWithScheme;
        }

        int at = authority.lastIndexOf('@');
        String userInfo = at >= 0 ? authority.substring(0, at + 1) : "";
        String hostAndPort = authority.substring(at + 1);

        String host = hostAndPort;
        String port = "";
        if (hostAndPort.startsWith("[")) {
            int close = hostAndPort.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("Invalid host");
            }
            host = hostAndPort.substring(0, close + 1);
            port = hostAndPort.substring(close + 1);
        } else {
            int colon = hostAndPort.lastIndexOf(':');
            if (colon >= 0) {
                host = hostAndPort.substring(0, colon);
                port = hostAndPort.substring(colon);
            }
        }

        String asciiHost = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED);

        // Characters like a full-width slash can turn into a real delimiter after
        // conversion. Only plain host characters are allowed through.
        if (!SAFE_ASCII_HOST.matcher(asciiHost).matches()) {
            throw new IllegalArgumentException("Invalid host");
        }

        return urlWithScheme.substring(0, authorityStart)
                + userInfo + asciiHost + port
                + urlWithScheme.substring(authorityEnd);
    }

    public static boolean isIpHost(String host) {
        if (host.startsWith("[")) {
            return true; // IPv6 literal
        }
        return IPV4.matcher(host).matches() || NUMERIC_HOST.matcher(host).matches();
    }

    /**
     * How many labels (from the right) make up the registrable domain:
     * 2 for example.com, 3 for example.co.uk.
     */
    public static int registrableLabelCount(String[] labels) {
        if (labels.length >= 3) {
            String last = labels[labels.length - 1];
            String secondLast = labels[labels.length - 2];
            if (last.length() == 2 && SECOND_LEVEL_LABELS.contains(secondLast)) {
                return 3;
            }
        }
        return 2;
    }

    private static boolean isAscii(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 127) {
                return false;
            }
        }
        return true;
    }
}