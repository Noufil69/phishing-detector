package com.noufil.phishingdetector.controller;

import java.util.Optional;
import java.util.regex.Pattern;

import com.noufil.phishingdetector.heuristics.HostExtractor;

/**
 * Checks the pasted text before any heuristic runs (TRD section 4: empty and
 * malformed input is rejected with a clear message).
 *
 * Pure string work. The messages never contain the submitted text.
 */
final class UrlInputValidator {

    static final int MAX_LENGTH = 2048;

    // Without "://", only "host" or "host:port" is accepted. That keeps text such as
    // "mailto:someone@example.com" or "user@example.com" from being read as a web address.
    private static final Pattern PLAIN_AUTHORITY = Pattern.compile("^[^:@]+(:\\d{1,5})?$");
    private static final Pattern IPV6_AUTHORITY = Pattern.compile("^\\[[0-9A-Fa-f:.]+\\](:\\d{1,5})?$");

    private static final String NOT_A_WEB_ADDRESS =
            "That does not look like a web address. Use a link starting with http:// or https://, "
                    + "or just a domain name like example.com.";

    private UrlInputValidator() {
    }

    /** @return the trimmed URL, ready to be checked */
    static String validate(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidUrlException("Please enter a URL to check.");
        }

        String url = raw.trim();

        if (url.length() > MAX_LENGTH) {
            throw new InvalidUrlException("That URL is too long. The limit is " + MAX_LENGTH + " characters.");
        }

        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                throw new InvalidUrlException("The URL cannot contain spaces or control characters.");
            }
        }

        if (!url.contains("://")) {
            int end = 0;
            while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) {
                end++;
            }
            String authority = url.substring(0, end);
            if (!PLAIN_AUTHORITY.matcher(authority).matches() && !IPV6_AUTHORITY.matcher(authority).matches()) {
                throw new InvalidUrlException(NOT_A_WEB_ADDRESS);
            }
        }

        Optional<String> host = HostExtractor.extractHost(url);
        if (host.isEmpty()) {
            throw new InvalidUrlException(NOT_A_WEB_ADDRESS);
        }

        String name = host.get();
        if (!HostExtractor.isIpHost(name) && !name.contains(".")) {
            throw new InvalidUrlException("Please include a full domain name, like example.com.");
        }

        return url;
    }
}