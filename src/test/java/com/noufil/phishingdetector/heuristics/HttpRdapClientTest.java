package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;
import com.sun.net.httpserver.HttpServer;

/**
 * Uses a tiny local web server standing in for the registry, so these tests
 * never touch the internet. The server listens on the loopback interface only.
 */
class HttpRdapClientTest {

    private static final String RDAP_BODY =
            "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2021-03-04T05:06:07Z\"}]}";

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
    }

    /** Starts a server that answers every request the same way, and returns a client pointed at it. */
    private HttpRdapClient clientAnswering(int status, String body, String locationHeader) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            if (locationHeader != null) {
                exchange.getResponseHeaders().add("Location", locationHeader);
            }
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            }
            exchange.close();
        });
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/domain/";
        return new HttpRdapClient(2000, baseUrl);
    }

    @Test
    void returnsRegistrationDateFromRegistryResponse() throws Exception {
        HttpRdapClient client = clientAnswering(200, RDAP_BODY, null);
        Optional<Instant> result = client.fetchRegistrationDate("example.com");
        assertEquals(Instant.parse("2021-03-04T05:06:07Z"), result.get());
    }

    @Test
    void notFoundMeansNoRecord() throws Exception {
        HttpRdapClient client = clientAnswering(404, "", null);
        assertTrue(client.fetchRegistrationDate("example.com").isEmpty());
    }

    @Test
    void responseWithoutRegistrationEventMeansNoRecord() throws Exception {
        HttpRdapClient client = clientAnswering(200, "{\"events\":[]}", null);
        assertTrue(client.fetchRegistrationDate("example.com").isEmpty());
    }

    @Test
    void serverErrorIsAnIoException() throws Exception {
        HttpRdapClient client = clientAnswering(500, "oops", null);
        assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void oversizedResponseIsRefused() throws Exception {
        String huge = "x".repeat(HttpRdapClient.MAX_BODY_BYTES + 100_000);
        HttpRdapClient client = clientAnswering(200, huge, null);
        assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectToLoopbackIsBlocked() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "https://127.0.0.1/domain/example.com");
        assertThrows(BlockedAddressException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectToPrivateNetworkIsBlocked() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "https://10.0.0.5/domain/example.com");
        assertThrows(BlockedAddressException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectToCloudMetadataAddressIsBlocked() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "https://169.254.169.254/latest/meta-data/");
        assertThrows(BlockedAddressException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectToPlainHttpIsRefused() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "http://example.org/domain/example.com");
        assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectToUnusualPortIsRefusedBeforeAnyConnection() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "https://8.8.8.8:8443/domain/example.com");
        IOException e = assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
        // refused by the port rule, not by the address rule
        assertFalse(e instanceof BlockedAddressException);
    }

    @Test
    void relativeRedirectBackToPlainHttpIsRefused() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", "/somewhere/else");
        assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void redirectWithoutLocationIsAnError() throws Exception {
        HttpRdapClient client = clientAnswering(302, "", null);
        assertThrows(IOException.class, () -> client.fetchRegistrationDate("example.com"));
    }

    @Test
    void invalidDomainsAreRejectedBeforeAnyRequestIsMade() {
        // Port 1 is closed, so reaching the network would fail differently and slowly.
        HttpRdapClient client = new HttpRdapClient(500, "http://127.0.0.1:1/domain/");
        String[] bad = {
                "", "localhost", "exa mple.com", "example.com/../x", "example.com?x=1",
                "example.com#frag", "evil.com@127.0.0.1", "-bad.com", "bad-.com",
                "exa_mple.com", "example..com", "http://example.com", "example.com:8080"
        };
        for (String domain : bad) {
            assertThrows(IOException.class, () -> client.fetchRegistrationDate(domain));
        }
    }

    @Test
    void nullDomainIsRejected() {
        HttpRdapClient client = new HttpRdapClient(500, "http://127.0.0.1:1/domain/");
        assertThrows(IOException.class, () -> client.fetchRegistrationDate(null));
    }
}