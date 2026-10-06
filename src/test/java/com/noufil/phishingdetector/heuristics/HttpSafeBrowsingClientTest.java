package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.SafeBrowsingClient.NotConfiguredException;
import com.sun.net.httpserver.HttpServer;

/**
 * Uses a tiny local web server standing in for Google, so these tests never touch
 * the internet and never use a real API key. The server listens on loopback only.
 */
class HttpSafeBrowsingClientTest {

    private static final String FAKE_KEY = "TESTKEY-1234567890-abcdef";

    private HttpServer server;
    private final List<String> requestLines = new CopyOnWriteArrayList<>();
    private final List<String> requestBodies = new CopyOnWriteArrayList<>();
    private final List<String> contentTypes = new CopyOnWriteArrayList<>();

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    private String startServer(int status, String body, String locationHeader, long delayMillis) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            requestLines.add(exchange.getRequestMethod() + " " + exchange.getRequestURI());
            contentTypes.add(String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")));
            requestBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            if (locationHeader != null) {
                exchange.getResponseHeaders().add("Location", locationHeader);
            }
            try {
                exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
                if (bytes.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(bytes);
                    }
                }
            } catch (IOException ignored) {
                // the client may already have given up (timeout test)
            }
            exchange.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/v4/threatMatches:find";
    }

    private HttpSafeBrowsingClient clientAnswering(int status, String body) throws IOException {
        return new HttpSafeBrowsingClient(FAKE_KEY, 2000, startServer(status, body, null, 0));
    }

    @Test
    void emptyObjectMeansNoThreats() throws IOException {
        assertTrue(clientAnswering(200, "{}").findThreats("http://example.com/").isEmpty());
    }

    @Test
    void matchesAreReturned() throws IOException {
        HttpSafeBrowsingClient c = clientAnswering(200,
                "{\"matches\":[{\"threatType\":\"SOCIAL_ENGINEERING\"},{\"threatType\":\"MALWARE\"}]}");
        assertEquals(List.of("SOCIAL_ENGINEERING", "MALWARE"), c.findThreats("http://bad.example/"));
    }

    @Test
    void sendsAPostWithTheKeyAndTheUrlInsideAJsonBody() throws IOException {
        clientAnswering(200, "{}").findThreats("http://example.com/a\"b?x=1&y=2");

        assertEquals(1, requestLines.size());
        assertEquals("POST /v4/threatMatches:find?key=" + FAKE_KEY, requestLines.get(0));
        assertEquals("application/json", contentTypes.get(0));

        Map<?, ?> body = (Map<?, ?>) MiniJson.parse(requestBodies.get(0));
        Map<?, ?> info = (Map<?, ?>) body.get("threatInfo");
        assertEquals(List.of("URL"), info.get("threatEntryTypes"));
        assertTrue(((List<?>) info.get("threatTypes")).contains("SOCIAL_ENGINEERING"));
        Map<?, ?> entry = (Map<?, ?>) ((List<?>) info.get("threatEntries")).get(0);
        assertEquals("http://example.com/a\"b?x=1&y=2", entry.get("url"));
    }

    @Test
    void missingKeyIsReportedAsNotConfiguredWithoutAnyRequest() throws IOException {
        String endpoint = startServer(200, "{}", null, 0);
        assertThrows(NotConfiguredException.class,
                () -> new HttpSafeBrowsingClient("", 2000, endpoint).findThreats("http://example.com/"));
        assertThrows(NotConfiguredException.class,
                () -> new HttpSafeBrowsingClient("   ", 2000, endpoint).findThreats("http://example.com/"));
        assertThrows(NotConfiguredException.class,
                () -> new HttpSafeBrowsingClient(null, 2000, endpoint).findThreats("http://example.com/"));
        assertTrue(requestLines.isEmpty());
    }

    @Test
    void aKeyWithOddCharactersIsTreatedAsNotConfigured() throws IOException {
        String endpoint = startServer(200, "{}", null, 0);
        assertThrows(NotConfiguredException.class,
                () -> new HttpSafeBrowsingClient("bad key&x=1/../..", 2000, endpoint)
                        .findThreats("http://example.com/"));
        assertTrue(requestLines.isEmpty());
    }

    @Test
    void errorStatusesAreErrorsAndNeverLeakTheKey() throws IOException {
        for (int status : new int[] {400, 403, 429, 500, 503}) {
            HttpSafeBrowsingClient c = clientAnswering(status, "{\"error\":{\"message\":\"key " + FAKE_KEY + " bad\"}}");
            IOException e = assertThrows(IOException.class, () -> c.findThreats("http://example.com/"));
            assertFalse(e.getMessage().contains(FAKE_KEY), "status " + status);
            stopServer();
        }
    }

    @Test
    void redirectsAreNeverFollowed() throws IOException {
        String endpoint = startServer(302, "", "/somewhere-else", 0);
        HttpSafeBrowsingClient c = new HttpSafeBrowsingClient(FAKE_KEY, 2000, endpoint);
        assertThrows(IOException.class, () -> c.findThreats("http://example.com/"));
        assertEquals(1, requestLines.size());
    }

    @Test
    void garbageResponseIsAnErrorNotAllClear() throws IOException {
        assertThrows(IOException.class, () -> clientAnswering(200, "<html>captive portal</html>")
                .findThreats("http://example.com/"));
    }

    @Test
    void unrecognisedJsonIsAnErrorNotAllClear() throws IOException {
        assertThrows(IOException.class, () -> clientAnswering(200, "{\"something\":\"else\"}")
                .findThreats("http://example.com/"));
    }

    @Test
    void oversizedResponseIsRejected() throws IOException {
        String huge = "{\"matches\":[]," + "\"pad\":\"" + "a".repeat(HttpSafeBrowsingClient.MAX_BODY_BYTES) + "\"}";
        assertThrows(IOException.class, () -> clientAnswering(200, huge).findThreats("http://example.com/"));
    }

    @Test
    void unreachableServerIsAnErrorWithoutTheKeyInTheMessage() throws IOException {
        String endpoint = startServer(200, "{}", null, 0);
        server.stop(0);
        server = null;
        IOException e = assertThrows(IOException.class,
                () -> new HttpSafeBrowsingClient(FAKE_KEY, 1000, endpoint).findThreats("http://example.com/"));
        assertFalse(e.getMessage().contains(FAKE_KEY));
    }

    @Test
    void slowServerTimesOut() throws IOException {
        String endpoint = startServer(200, "{}", null, 1500);
        HttpSafeBrowsingClient c = new HttpSafeBrowsingClient(FAKE_KEY, 300, endpoint);
        IOException e = assertThrows(IOException.class, () -> c.findThreats("http://example.com/"));
        assertFalse(e.getMessage().contains(FAKE_KEY));
    }

    // ---------- request building ----------

    @Test
    void jsonStringEscapesQuotesBackslashesAndControlCharacters() {
        assertEquals("\"a\\\"b\\\\c\\nd\\te\\u0001\"", HttpSafeBrowsingClient.jsonString("a\"b\\c\nd\te\u0001"));
    }

    @Test
    void jsonStringKeepsTheOutputPlainAscii() {
        assertEquals("\"m\\u00fcnchen\"", HttpSafeBrowsingClient.jsonString("m\u00fcnchen"));
        String out = HttpSafeBrowsingClient.jsonString("\u0430\uff0f\ud83d\ude00");
        for (char c : out.toCharArray()) {
            assertTrue(c >= 0x20 && c < 0x7f);
        }
    }

    @Test
    void aHostileUrlCannotChangeTheStructureOfTheRequest() {
        String hostile = "http://e.com/\",\"threatTypes\":[],\"x\":\"";
        Map<?, ?> body = (Map<?, ?>) MiniJson.parse(HttpSafeBrowsingClient.requestBody(hostile));
        Map<?, ?> info = (Map<?, ?>) body.get("threatInfo");
        assertEquals(4, ((List<?>) info.get("threatTypes")).size());
        List<?> entries = (List<?>) info.get("threatEntries");
        assertEquals(1, entries.size());
        assertEquals(hostile, ((Map<?, ?>) entries.get(0)).get("url"));
        assertEquals(List.of("client", "threatInfo"), new ArrayList<>(body.keySet()));
    }
}