package com.noufil.phishingdetector.heuristics;

import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
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
 * It uses MiniJson (a small reader that limits nesting depth and never echoes the
 * input in errors) and returns "empty" for anything it cannot understand instead
 * of throwing.
 */
public final class RdapResponseParser {

    private RdapResponseParser() {
    }

    /** The earliest "registration" event date found, or empty. */
    public static Optional<Instant> registrationDate(String json) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }

        Object root;
        try {
            root = MiniJson.parse(json);
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
}