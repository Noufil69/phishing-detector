package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Reads the answer of the Safe Browsing "threatMatches.find" call.
 *
 * No threats:  {}
 * Threats:     {"matches":[{"threatType":"SOCIAL_ENGINEERING", ...}]}
 * Anything else is rejected.
 *
 * The answer comes from a remote server, so it is untrusted. The important rule:
 * an answer that cannot be understood is an ERROR, never "no threats". Otherwise a
 * broken or tampered response would make a dangerous URL look safe.
 */
final class SafeBrowsingResponseParser {

    private static final Pattern THREAT_NAME = Pattern.compile("^[A-Z_]{1,64}$");
    static final String UNKNOWN_THREAT = "UNKNOWN";

    private SafeBrowsingResponseParser() {
    }

    /**
     * @return the distinct threat types, in the order they appear (empty if none)
     * @throws IOException if the response is not a valid answer
     */
    static List<String> threatTypes(String json) throws IOException {
        if (json == null || json.isBlank()) {
            throw new IOException("Unreadable Safe Browsing response");
        }

        Object root;
        try {
            root = MiniJson.parse(json);
        } catch (IllegalArgumentException e) {
            throw new IOException("Unreadable Safe Browsing response");
        }

        if (!(root instanceof Map<?, ?> document)) {
            throw new IOException("Unreadable Safe Browsing response");
        }

        // The real "no threats" answer is exactly {}. Any other object without
        // "matches" is something we do not recognise, so it is an error.
        if (document.isEmpty()) {
            return List.of();
        }
        if (!(document.get("matches") instanceof List<?> list)) {
            throw new IOException("Unreadable Safe Browsing response");
        }

        List<String> found = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> match)) {
                throw new IOException("Unreadable Safe Browsing response");
            }
            String type = UNKNOWN_THREAT;
            if (match.get("threatType") instanceof String text && THREAT_NAME.matcher(text).matches()) {
                type = text;
            }
            if (!found.contains(type)) {
                found.add(type);
            }
        }
        return List.copyOf(found);
    }
}