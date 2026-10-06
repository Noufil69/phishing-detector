package com.noufil.phishingdetector.heuristics;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class MiniJsonTest {

    @Test
    void parsesObjectsArraysAndScalars() {
        Object root = MiniJson.parse("{\"a\":[1,true,null,\"x\"],\"b\":{\"c\":2.5}}");
        Map<?, ?> map = (Map<?, ?>) root;
        List<?> list = (List<?>) map.get("a");
        assertEquals(1.0, list.get(0));
        assertEquals(Boolean.TRUE, list.get(1));
        assertNull(list.get(2));
        assertEquals("x", list.get(3));
        assertEquals(2.5, ((Map<?, ?>) map.get("b")).get("c"));
    }

    @Test
    void decodesEscapes() {
        assertEquals("A\n\"\\", MiniJson.parse("\"\\u0041\\n\\\"\\\\\""));
    }

    @Test
    void bracesAndQuotesInsideStringsAreJustText() {
        assertEquals("}{]\"[", MiniJson.parse("\"}{]\\\"[\""));
    }

    @Test
    void emptyContainersAreFine() {
        assertTrue(((Map<?, ?>) MiniJson.parse("{}")).isEmpty());
        assertTrue(((List<?>) MiniJson.parse(" [ ] ")).isEmpty());
    }

    @Test
    void trailingGarbageIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("{} x"));
    }

    @Test
    void brokenInputIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("{\"a\":"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("{\"a\" 1}"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("[1,]"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("\"abc"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(""));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(null));
    }

    @Test
    void reasonablyDeepNestingWorks() {
        assertTrue(MiniJson.parse("[".repeat(20) + "]".repeat(20)) instanceof List);
    }

    @Test
    void hostileDeepNestingIsRejectedWithoutOverflowingTheStack() {
        assertThrows(IllegalArgumentException.class,
                () -> MiniJson.parse("[".repeat(100_000) + "]".repeat(100_000)));
    }

    @Test
    void errorMessageNeverEchoesTheInput() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MiniJson.parse("{\"secret-token-123\": oops}"));
        assertFalse(e.getMessage().contains("secret-token-123"));
    }
}