package com.noufil.phishingdetector.heuristics;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Heuristic 1: structural red flags.
 *
 * Looks only at the text of the URL itself. It never makes a network call and
 * never fetches the page (SSRF boundary, see docs/SECURITY.md).
 *
 * Each red flag adds points. The total is capped at 100.
 */
@Component
public class StructuralHeuristic implements HeuristicCheck {

    static final String NAME = "Structural";

    // Points per red flag
    static final int POINTS_UNPARSEABLE = 30;
    static final int POINTS_UNSUPPORTED_SCHEME = 60;
    static final int POINTS_IP_HOST = 40;
    static final int POINTS_USERINFO = 30;
    static final int POINTS_SHORTENER = 25;
    static final int POINTS_DEEP_SUBDOMAINS = 25;
    static final int POINTS_SOME_SUBDOMAINS = 10;
    static final int POINTS_SUSPICIOUS_TLD = 20;
    static final int POINTS_PUNYCODE = 20;
    static final int POINTS_MANY_HYPHENS = 10;
    static final int POINTS_LONG_URL = 10;
    static final int POINTS_PLAIN_HTTP = 10;

    private static final int LONG_URL_LENGTH = 100;

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    // Hosts written as one big number (3232235777) or hex (0xC0A80001) are also IPs.
    private static final Pattern NUMERIC_HOST = Pattern.compile("^(0x[0-9a-f]+|\\d+)$");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
            "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc");

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
            "click", "country", "work", "support", "rest", "icu", "buzz",
            "monster", "cyou", "sbs");

    // Second-level labels that act like part of the public suffix (co.uk, com.pk, ...).
    // Simplified on purpose: a full Public Suffix List is overkill for a heuristic.
    private static final Set<String> SECOND_LEVEL_LABELS = Set.of(
            "co", "com", "org", "net", "gov", "edu", "ac");

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public RiskFactor evaluate(String url) {
        String trimmed = url.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);

        if (lower.startsWith("javascript:") || lower.startsWith("data:")
                || lower.startsWith("file:") || lower.startsWith("ftp://")) {
            return RiskFactor.of(NAME, POINTS_UNSUPPORTED_SCHEME,
                    "Not a normal web link (unsupported or dangerous URL scheme)");
        }

        boolean schemeAssumed = !trimmed.contains("://");
        String normalized = schemeAssumed ? "http://" + trimmed : trimmed;

        URI uri;
        try {
            uri = new URI(normalized);
        } catch (URISyntaxException e) {
            return unparseable();
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return RiskFactor.of(NAME, POINTS_UNSUPPORTED_SCHEME,
                    "Not a normal web link (unsupported or dangerous URL scheme)");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return unparseable();
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        List<String> findings = new ArrayList<>();
        int score = 0;

        boolean ipHost = isIpHost(host);

        if (ipHost) {
            score += POINTS_IP_HOST;
            findings.add("uses a raw IP address instead of a domain name");
        }

        if (uri.getRawUserInfo() != null) {
            score += POINTS_USERINFO;
            findings.add("contains '@', which can disguise the real destination");
        }

        if (!ipHost) {
            if (isShortener(host)) {
                score += POINTS_SHORTENER;
                findings.add("is a link shortener that hides the final destination");
            }

            String[] labels = host.split("\\.");

            String tld = labels[labels.length - 1];
            if (SUSPICIOUS_TLDS.contains(tld)) {
                score += POINTS_SUSPICIOUS_TLD;
                findings.add("uses the ." + tld + " ending, which is common in abusive domains");
            }

            int subdomains = countSubdomains(labels);
            if (subdomains >= 3) {
                score += POINTS_DEEP_SUBDOMAINS;
                findings.add("has " + subdomains + " subdomain levels, often used to fake a trusted name");
            } else if (subdomains == 2) {
                score += POINTS_SOME_SUBDOMAINS;
                findings.add("has 2 subdomain levels");
            }

            for (String label : labels) {
                if (label.startsWith("xn--")) {
                    score += POINTS_PUNYCODE;
                    findings.add("contains an internationalised (punycode) label that may imitate another site");
                    break;
                }
            }

            // Punycode labels (xn--...) contain hyphens by design, so don't count them here.
            int hyphens = 0;
            for (String label : labels) {
                if (!label.startsWith("xn--")) {
                    hyphens += countChar(label, '-');
                }
            }
            if (hyphens >= 3) {
                score += POINTS_MANY_HYPHENS;
                findings.add("has many hyphens in the domain name");
            }
        }

        if (trimmed.length() > LONG_URL_LENGTH) {
            score += POINTS_LONG_URL;
            findings.add("is unusually long");
        }

        if (!schemeAssumed && scheme.equals("http")) {
            score += POINTS_PLAIN_HTTP;
            findings.add("does not use HTTPS");
        }

        if (findings.isEmpty()) {
            return RiskFactor.of(NAME, 0, "No structural red flags found");
        }

        int capped = Math.min(score, 100);
        return RiskFactor.of(NAME, capped, "The URL " + String.join("; ", findings));
    }

    private RiskFactor unparseable() {
        return RiskFactor.of(NAME, POINTS_UNPARSEABLE,
                "The URL is malformed or has no valid host name");
    }

    private boolean isIpHost(String host) {
        if (host.startsWith("[")) {
            return true; // IPv6 literal
        }
        return IPV4.matcher(host).matches() || NUMERIC_HOST.matcher(host).matches();
    }

    private boolean isShortener(String host) {
        for (String shortener : SHORTENERS) {
            if (host.equals(shortener) || host.endsWith("." + shortener)) {
                return true;
            }
        }
        return false;
    }

    /** Subdomains = total labels minus the registrable domain (e.g. example.com or example.co.uk). */
    private int countSubdomains(String[] labels) {
        int registrableLabels = 2;
        if (labels.length >= 3) {
            String last = labels[labels.length - 1];
            String secondLast = labels[labels.length - 2];
            if (last.length() == 2 && SECOND_LEVEL_LABELS.contains(secondLast)) {
                registrableLabels = 3;
            }
        }
        return Math.max(0, labels.length - registrableLabels);
    }

    private int countChar(String s, char c) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) {
                count++;
            }
        }
        return count;
    }
}