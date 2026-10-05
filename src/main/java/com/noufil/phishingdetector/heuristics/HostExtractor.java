package com.noufil.phishingdetector.heuristics;

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
 */
public final class HostExtractor {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern NUMERIC_HOST = Pattern.compile("^(0x[0-9a-f]+|\\d+)$");

    // Second-level labels that act like part of the public suffix (co.uk, com.pk, ...).
    private static final Set<String> SECOND_LEVEL_LABELS = Set.of(
            "co", "com", "org", "net", "gov", "edu", "ac");

    private HostExtractor() {
    }

    /**
     * Returns the lower-case host, or empty if the URL has no usable http(s) host.
     * A URL without a scheme (for example "paypa1.com/login") is treated as http.
     */
    public static Optional<String> extractHost(String url) {
        if (url == null) {
            return Optional.empty();
        }
        String trimmed = url.trim();
        String normalized = trimmed.contains("://") ? trimmed : "http://" + trimmed;

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
}