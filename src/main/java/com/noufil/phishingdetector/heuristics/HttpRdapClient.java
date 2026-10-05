package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Real RdapClient. Asks an RDAP bootstrap service (rdap.org by default), which
 * redirects to the registry that owns the domain.
 *
 * Safety rules (see docs/SECURITY.md):
 *  - The domain is validated to plain letters, digits, hyphens and dots before it
 *    is placed into a URL, so it cannot inject paths, queries or other hosts.
 *  - Redirects are never followed automatically. Each one is checked by hand:
 *    https only, port 443 only, and the host must resolve to public addresses.
 *  - Redirects are limited to a few hops.
 *  - Response size is capped.
 *  - Connect and response timeouts apply.
 *  - The first URL comes from configuration (trusted), never from the user.
 */
@Component
public class HttpRdapClient implements RdapClient {

    static final int MAX_BODY_BYTES = 1_000_000;
    static final int MAX_REDIRECTS = 4;

    private static final Pattern VALID_DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");

    private final HttpClient http;
    private final Duration timeout;
    private final String baseUrl;

    public HttpRdapClient(
            @Value("${heuristics.http-timeout-ms:4000}") int timeoutMs,
            @Value("${rdap.base-url:https://rdap.org/domain/}") String baseUrl) {
        this.timeout = Duration.ofMillis(timeoutMs);
        this.baseUrl = baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public Optional<Instant> fetchRegistrationDate(String domain) throws IOException {
        if (domain == null || !VALID_DOMAIN.matcher(domain).matches()) {
            throw new IOException("Not a valid domain name");
        }

        URI uri = URI.create(baseUrl + domain);

        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            HttpResponse<InputStream> response = send(uri);
            int status = response.statusCode();

            if (status >= 300 && status < 400) {
                String location = response.headers().firstValue("Location").orElse(null);
                closeQuietly(response.body());
                if (location == null) {
                    throw new IOException("Redirect without a location");
                }
                uri = checkedRedirectTarget(uri, location);
                continue;
            }

            if (status == 404) {
                closeQuietly(response.body());
                return Optional.empty();
            }

            if (status != 200) {
                closeQuietly(response.body());
                throw new IOException("Unexpected response from registry");
            }

            return RdapResponseParser.registrationDate(readCapped(response.body()));
        }
        throw new IOException("Too many redirects");
    }

    private HttpResponse<InputStream> send(URI uri) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", "application/rdap+json, application/json")
                .header("User-Agent", "phishing-detector/0.1")
                .GET()
                .build();
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while contacting the registry");
        }
    }

    /** SSRF guard for redirects: https, port 443, public addresses only. */
    private URI checkedRedirectTarget(URI current, String location) throws IOException {
        URI next;
        try {
            next = current.resolve(location);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid redirect target");
        }

        if (!"https".equalsIgnoreCase(next.getScheme()) || next.getHost() == null) {
            throw new IOException("Redirect target refused: not https");
        }
        if (next.getPort() != -1 && next.getPort() != 443) {
            throw new IOException("Redirect target refused: unexpected port");
        }
        PublicAddressValidator.resolvePublic(next.getHost());
        return next;
    }

    private String readCapped(InputStream body) throws IOException {
        try (InputStream in = body) {
            byte[] data = in.readNBytes(MAX_BODY_BYTES + 1);
            if (data.length > MAX_BODY_BYTES) {
                throw new IOException("Registry response too large");
            }
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    private void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException ignored) {
            // nothing useful to do
        }
    }
}