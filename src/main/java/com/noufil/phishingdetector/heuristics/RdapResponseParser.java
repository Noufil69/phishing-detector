package com.noufil.phishingdetector.heuristics;

import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Extracts the registration date from an RDAP domain response.
 *
 * RDAP answers look like:
 * {"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}, ...]}
 *
 * The response comes from a remote server, so it is treated as untrusted input.
 * This class contains its own small JSON reader that:
 *  - limits nesting depth, so a hostile "[[[[[..." cannot overflow the stack
 *  - never returns an error message containing the input
 *  - returns "empty" for anything it cannot understand instead of throwing
 */
public final class RdapResponseParser {

    static final int MAX_DEPTH = 32;

    private RdapResponseParser() {
    }

    /** The earliest "registration" event date found, or empty. */
    public static Optional<Instant> registrationDate(String json) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }

        Object root;
        try {
            root = new Reader(json).readDocument();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }

        if (!(root instanceof Map<?, ?> document)) {
            return Optional.empty();
        }
        if (!(document.get("events") instanceof List<?> events)) {
            return Optional.empty();
        }

        Instant earliest = null;
        for (Object item : events) {
            if (item instanceof Map<?, ?> event
                    && "registration".equals(event.get("eventAction"))
                    && event.get("eventDate") instanceof String dateText) {
                Optional<Instant> parsed = parseDate(dateText);
                if (parsed.isPresent() && (earliest == null || parsed.get().isBefore(earliest))) {
                    earliest = parsed.get();
                }
            }
        }
        return Optional.ofNullable(earliest);
    }

    private static Optional<Instant> parseDate(String text) {
        try {
            return Optional.of(OffsetDateTime.parse(text).toInstant());
        } catch (DateTimeParseException ignored) {
            // fall through to the date-only form
        }
        try {
            return Optional.of(LocalDate.parse(text).atStartOfDay(ZoneOffset.UTC).toInstant());
        } catch (DateTimeParseException ignored) {
            return Optional.empty();
        }
    }

    /** Minimal recursive-descent JSON reader. Produces Map, List, String, Double, Boolean or null. */
    private static final class Reader {

        private final String text;
        private int pos = 0;

        Reader(String text) {
            this.text = text;
        }

        Object readDocument() {
            Object value = readValue(0);
            skipWhitespace();
            if (pos != text.length()) {
                throw invalid();
            }
            return value;
        }

        private IllegalArgumentException invalid() {
            return new IllegalArgumentException("Invalid JSON");
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw invalid();
            }
            skipWhitespace();
            if (pos >= text.length()) {
                throw invalid();
            }
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> readObject(depth);
                case '[' -> readArray(depth);
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Object readLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw invalid();
            }
            pos += literal.length();
            return value;
        }

        private Object readNumber() {
            int start = pos;
            while (pos < text.length() && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) {
                pos++;
            }
            if (start == pos) {
                throw invalid();
            }
            try {
                return Double.parseDouble(text.substring(start, pos));
            } catch (NumberFormatException e) {
                throw invalid();
            }
        }

        private String readString() {
            if (pos >= text.length() || text.charAt(pos) != '"') {
                throw invalid();
            }
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= text.length()) {
                    throw invalid();
                }
                char escape = text.charAt(pos++);
                switch (escape) {
                    case '"', '\\', '/' -> sb.append(escape);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > text.length()) {
                            throw invalid();
                        }
                        try {
                            sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException e) {
                            throw invalid();
                        }
                        pos += 4;
                    }
                    default -> throw invalid();
                }
            }
        }

        private Map<String, Object> readObject(int depth) {
            pos++; // skip '{'
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                if (pos >= text.length() || text.charAt(pos) != ':') {
                    throw invalid();
                }
                pos++;
                map.put(key, readValue(depth + 1));
                skipWhitespace();
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw invalid();
                }
            }
        }

        private List<Object> readArray(int depth) {
            pos++; // skip '['
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue(depth + 1));
                skipWhitespace();
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw invalid();
                }
            }
        }
    }
}