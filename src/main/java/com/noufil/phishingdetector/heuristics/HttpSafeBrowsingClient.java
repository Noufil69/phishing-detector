package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Real SafeBrowsingClient. Calls Google's Safe Browsing Lookup API (v4).
 *
 * Privacy: the submitted URL is sent to Google. The page must say so. Nothing is
 * stored or logged here.
 *
 * Safety rules (see docs/SECURITY.md):
 *  - The API key comes only from configuration (environment variable), never from code.
 *  - The key never appears in an error message or a reason text.
 *  - The endpoint comes from configuration (trusted), never from the user, and
 *    redirects are never followed.
 *  - The submitted URL is placed into a JSON body with full escaping, so it cannot
 *    change the structure of the request.
 *  - Response size is capped, and connect and response timeouts apply.
 */
@Component
public class HttpSafeBrowsingClient implements SafeBrowsingClient {

    static final int MAX_BODY_BYTES = 1_000_000;

    private static final Logger log = LoggerFactory.getLogger(HttpSafeBrowsingClient.class);

    private static final Pattern PLAIN_KEY = Pattern.compile("^[A-Za-z0-9_-]{10,200}$");

    private final HttpClient http;
    private final Duration timeout;
    private final String endpoint;
    private final String apiKey;

    public HttpSafeBrowsingClient(
            @Value("${safebrowsing.api-key:}") String apiKey,
            @Value("${heuristics.http-timeout-ms:4000}") int timeoutMs,
            @Value("${safebrowsing.base-url:https://safebrowsing.googleapis.com/v4/threatMatches:find}") String endpoint) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.timeout = Duration.ofMillis(timeoutMs);
        this.endpoint = endpoint;
        this.http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public List<String> findThreats(String url) throws IOException {
        if (!PLAIN_KEY.matcher(apiKey).matches()) {
            throw new NotConfiguredException();
        }

        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(endpoint + "?key=" + URLEncoder.encode(apiKey, StandardCharsets.UTF_8)))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody(url), StandardCharsets.UTF_8))
                .build();

        HttpResponse<InputStream> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while contacting Safe Browsing");
        } catch (IOException e) {
            // The original message could contain the request address, which holds the key.
            // Log only the exception type, which is enough to tell a timeout from a refusal.
            log.warn("Safe Browsing request failed: {}", e.getClass().getSimpleName());
            throw new IOException("Could not reach Safe Browsing");
        }

        if (response.statusCode() != 200) {
            // The status code alone is safe to log and tells the developer what is wrong
            // (400 or 403 usually means the key is wrong or the API is not enabled for it).
            log.warn("Safe Browsing answered with HTTP {}", response.statusCode());
            closeQuietly(response.body());
            throw new IOException("Safe Browsing refused the request");
        }
        return SafeBrowsingResponseParser.threatTypes(readCapped(response.body()));
    }

    /** The JSON body for threatMatches.find. The URL is escaped; everything else is fixed text. */
    static String requestBody(String url) {
        return "{\"client\":{\"clientId\":\"phishing-detector\",\"clientVersion\":\"0.1\"},"
                + "\"threatInfo\":{"
                + "\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\","
                + "\"POTENTIALLY_HARMFUL_APPLICATION\"],"
                + "\"platformTypes\":[\"ANY_PLATFORM\"],"
                + "\"threatEntryTypes\":[\"URL\"],"
                + "\"threatEntries\":[{\"url\":" + jsonString(url) + "}]}}";
    }

    /** A JSON string literal. Quotes, backslashes, control and non-ASCII characters are escaped. */
    static String jsonString(String text) {
        StringBuilder sb = new StringBuilder(text.length() + 2);
        sb.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private String readCapped(InputStream body) throws IOException {
        try (InputStream in = body) {
            byte[] data = in.readNBytes(MAX_BODY_BYTES + 1);
            if (data.length > MAX_BODY_BYTES) {
                throw new IOException("Safe Browsing response too large");
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