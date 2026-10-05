package com.noufil.phishingdetector.heuristics;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class RdapResponseParserTest {

    private static final String REALISTIC = """
            {
              "objectClassName": "domain",
              "ldhName": "EXAMPLE.COM",
              "status": ["client delete prohibited"],
              "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"}
              ],
              "links": [{"rel": "self", "href": "https://rdap.example/domain/EXAMPLE.COM"}]
            }
            """;

    @Test
    void readsRegistrationDateFromRealisticResponse() {
        assertEquals(Instant.parse("1995-08-14T04:00:00Z"),
                RdapResponseParser.registrationDate(REALISTIC).get());
    }

    @Test
    void keyOrderInsideEventDoesNotMatter() {
        String json = "{\"events\":[{\"eventDate\":\"2020-01-02T03:04:05Z\",\"eventAction\":\"registration\"}]}";
        assertEquals(Instant.parse("2020-01-02T03:04:05Z"),
                RdapResponseParser.registrationDate(json).get());
    }

    @Test
    void earliestRegistrationEventWins() {
        String json = """
                {"events":[
                  {"eventAction":"registration","eventDate":"2022-05-05T00:00:00Z"},
                  {"eventAction":"registration","eventDate":"2019-01-01T00:00:00Z"}
                ]}""";
        assertEquals(Instant.parse("2019-01-01T00:00:00Z"),
                RdapResponseParser.registrationDate(json).get());
    }

    @Test
    void dateWithOffsetIsConvertedToUtc() {
        String json = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T05:00:00+05:00\"}]}";
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"),
                RdapResponseParser.registrationDate(json).get());
    }

    @Test
    void fractionalSecondsAreAccepted() {
        String json = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00.123Z\"}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isPresent());
    }

    @Test
    void dateOnlyFormIsAcceptedAsMidnightUtc() {
        String json = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-02\"}]}";
        assertEquals(Instant.parse("2020-01-02T00:00:00Z"),
                RdapResponseParser.registrationDate(json).get());
    }

    @Test
    void invalidDateGivesEmpty() {
        String json = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"not a date\"}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isEmpty());
    }

    @Test
    void noRegistrationEventGivesEmpty() {
        String json = "{\"events\":[{\"eventAction\":\"expiration\",\"eventDate\":\"2030-01-01T00:00:00Z\"}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isEmpty());
    }

    @Test
    void missingEventsGivesEmpty() {
        assertTrue(RdapResponseParser.registrationDate("{\"ldhName\":\"x.com\"}").isEmpty());
    }

    @Test
    void eventsOfWrongTypeGivesEmpty() {
        assertTrue(RdapResponseParser.registrationDate("{\"events\":\"nope\"}").isEmpty());
        assertTrue(RdapResponseParser.registrationDate("{\"events\":[1,2,\"x\",null]}").isEmpty());
    }

    @Test
    void rootThatIsNotAnObjectGivesEmpty() {
        assertTrue(RdapResponseParser.registrationDate("[1,2,3]").isEmpty());
        assertTrue(RdapResponseParser.registrationDate("\"text\"").isEmpty());
    }

    @Test
    void bracesAndQuotesInsideStringsDoNotConfuseTheReader() {
        String json = """
                {"note":"a } b ] \\" c","events":[{"eventAction":"registration","eventDate":"2000-01-01T00:00:00Z"}]}""";
        assertEquals(Instant.parse("2000-01-01T00:00:00Z"),
                RdapResponseParser.registrationDate(json).get());
    }

    @Test
    void unicodeEscapesAreHandled() {
        String json = "{\"name\":\"\\u0041\\u00e9\",\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\"}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isPresent());
    }

    @Test
    void numbersBooleansAndNullsAreHandled() {
        String json = "{\"a\":1,\"b\":-2.5e3,\"c\":true,\"d\":false,\"e\":null,"
                + "\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\"}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isPresent());
    }

    @Test
    void malformedJsonGivesEmptyInsteadOfThrowing() {
        String[] broken = {
                "{not json",
                "{\"events\":[",
                "{\"events\":[{\"eventAction\":\"registration\",}]}",
                "{\"a\" 1}",
                "{\"a\":tru}",
                "{\"a\":\"unterminated}",
                "{\"a\":\"bad \\x escape\"}",
                "{\"a\":\"\\u00\"}",
                "{} trailing",
                "<html>not rdap</html>"
        };
        for (String text : broken) {
            assertEquals(Optional.empty(), RdapResponseParser.registrationDate(text));
        }
    }

    @Test
    void emptyAndNullInputGiveEmpty() {
        assertTrue(RdapResponseParser.registrationDate("").isEmpty());
        assertTrue(RdapResponseParser.registrationDate("   ").isEmpty());
        assertTrue(RdapResponseParser.registrationDate(null).isEmpty());
    }

    @Test
    void hostileDeepNestingIsRejectedWithoutStackOverflow() {
        String deepArray = "[".repeat(100_000) + "]".repeat(100_000);
        String deepObject = "{\"a\":".repeat(50_000) + "1" + "}".repeat(50_000);
        assertTrue(RdapResponseParser.registrationDate(deepArray).isEmpty());
        assertTrue(RdapResponseParser.registrationDate(deepObject).isEmpty());
    }

    @Test
    void nestingJustWithinTheLimitIsStillAccepted() {
        String json = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2000-01-01T00:00:00Z\","
                + "\"extra\":" + "[".repeat(10) + "]".repeat(10) + "}]}";
        assertTrue(RdapResponseParser.registrationDate(json).isPresent());
    }
}