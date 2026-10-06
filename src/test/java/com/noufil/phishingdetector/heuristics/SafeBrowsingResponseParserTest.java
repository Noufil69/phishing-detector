package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class SafeBrowsingResponseParserTest {

    @Test
    void emptyObjectMeansNoThreats() throws IOException {
        assertTrue(SafeBrowsingResponseParser.threatTypes("{}").isEmpty());
        assertTrue(SafeBrowsingResponseParser.threatTypes("  { }  ").isEmpty());
    }

    @Test
    void emptyMatchesListMeansNoThreats() throws IOException {
        assertTrue(SafeBrowsingResponseParser.threatTypes("{\"matches\":[]}").isEmpty());
    }

    @Test
    void oneMatchIsReturned() throws IOException {
        String json = "{\"matches\":[{\"threatType\":\"SOCIAL_ENGINEERING\",\"platformType\":\"ANY_PLATFORM\","
                + "\"threatEntryType\":\"URL\",\"threat\":{\"url\":\"http://x.example/\"},"
                + "\"cacheDuration\":\"300s\"}]}";
        assertEquals(List.of("SOCIAL_ENGINEERING"), SafeBrowsingResponseParser.threatTypes(json));
    }

    @Test
    void severalMatchesKeepTheirOrderAndDropDuplicates() throws IOException {
        String json = "{\"matches\":[{\"threatType\":\"MALWARE\"},{\"threatType\":\"SOCIAL_ENGINEERING\"},"
                + "{\"threatType\":\"MALWARE\"}]}";
        assertEquals(List.of("MALWARE", "SOCIAL_ENGINEERING"), SafeBrowsingResponseParser.threatTypes(json));
    }

    @Test
    void oddThreatNamesBecomeUnknownInsteadOfBeingPassedOn() throws IOException {
        String json = "{\"matches\":[{\"threatType\":\"<script>alert(1)</script>\"},{\"threatType\":\"lower\"},"
                + "{\"threatType\":42},{}]}";
        assertEquals(List.of("UNKNOWN"), SafeBrowsingResponseParser.threatTypes(json));
    }

    @Test
    void aMatchIsNeverLostEvenWhenItsTypeIsMissing() throws IOException {
        assertEquals(List.of("UNKNOWN"), SafeBrowsingResponseParser.threatTypes("{\"matches\":[{}]}"));
    }

    @Test
    void anObjectWeDoNotRecogniseIsAnErrorNotAllClear() {
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("{\"foo\":1}"));
        assertThrows(IOException.class,
                () -> SafeBrowsingResponseParser.threatTypes("{\"error\":{\"code\":400}}"));
    }

    @Test
    void wrongShapesAreErrors() {
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("[]"));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("\"text\""));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("{\"matches\":\"yes\"}"));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("{\"matches\":[1]}"));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("{\"matches\":null}"));
    }

    @Test
    void garbageBlankAndNullAreErrors() {
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("not json"));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("{\"matches\":["));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes(""));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes("   "));
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes(null));
    }

    @Test
    void hostileNestingIsAnErrorNotACrash() {
        assertThrows(IOException.class, () -> SafeBrowsingResponseParser.threatTypes(
                "{\"matches\":" + "[".repeat(50_000) + "]".repeat(50_000) + "}"));
    }

    @Test
    void errorMessageNeverEchoesTheResponse() {
        IOException e = assertThrows(IOException.class,
                () -> SafeBrowsingResponseParser.threatTypes("{\"leak-me-please\": oops"));
        assertFalse(e.getMessage().contains("leak-me-please"));
    }
}