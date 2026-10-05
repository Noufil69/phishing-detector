package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;
import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Heuristic 3: SSL/TLS certificate.
 *
 * Always checks port 443 of the host, even when the pasted URL says http://.
 * Only a TLS handshake is performed. The page itself is never requested.
 *
 * Reasons shown to the user are fixed sentences. Text from the certificate or
 * from exception messages is never copied into them, because that text is
 * controlled by whoever runs the site being checked.
 */
@Component
public class SslCertificateHeuristic implements HeuristicCheck {

    static final String NAME = "SSL Certificate";

    static final int POINTS_NO_HTTPS = 30;
    static final int POINTS_EXPIRED = 70;
    static final int POINTS_NOT_YET_VALID = 70;
    static final int POINTS_HOST_MISMATCH = 80;
    static final int POINTS_UNTRUSTED = 75;
    static final int POINTS_OTHER_HANDSHAKE_FAILURE = 70;
    static final int POINTS_OTHER_TLS_ERROR = 50;
    static final int POINTS_VERY_NEW_CERT = 15;
    static final int POINTS_EXPIRING_SOON = 10;

    static final int NEW_CERT_DAYS = 7;
    static final int EXPIRING_SOON_DAYS = 7;

    private final TlsInspector inspector;

    public SslCertificateHeuristic(TlsInspector inspector) {
        this.inspector = inspector;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public RiskFactor evaluate(String url) {
        Optional<String> hostOpt = HostExtractor.extractHost(url);
        if (hostOpt.isEmpty()) {
            return RiskFactor.unavailable(NAME, "No valid host name to check");
        }
        String host = hostOpt.get();

        if (HostExtractor.isIpHost(host)) {
            return RiskFactor.unavailable(NAME, "Certificate check does not apply to IP address hosts");
        }

        try {
            return assess(inspector.inspect(host));
        } catch (BlockedAddressException e) {
            return RiskFactor.unavailable(NAME, "Check skipped: the host does not point to a public internet address");
        } catch (UnknownHostException e) {
            return RiskFactor.unavailable(NAME, "The domain name does not resolve");
        } catch (SocketTimeoutException e) {
            return RiskFactor.unavailable(NAME, "Timed out while connecting to the site");
        } catch (ConnectException e) {
            if (messageContains(e, "timed out")) {
                return RiskFactor.unavailable(NAME, "Timed out while connecting to the site");
            }
            return RiskFactor.of(NAME, POINTS_NO_HTTPS, "The site does not offer a secure (HTTPS) connection");
        } catch (SSLHandshakeException e) {
            return classifyHandshakeFailure(e);
        } catch (SSLException e) {
            return RiskFactor.of(NAME, POINTS_OTHER_TLS_ERROR, "The secure connection to the site failed");
        } catch (IOException e) {
            return RiskFactor.unavailable(NAME, "Could not complete the certificate check");
        }
    }

    private RiskFactor assess(TlsInspector.CertificateInfo info) {
        Instant now = Instant.now();

        // Normally the handshake itself rejects these. Checked again as a safety net.
        if (info.notAfter().isBefore(now)) {
            return RiskFactor.of(NAME, POINTS_EXPIRED, "The site's security certificate has expired");
        }
        if (info.notBefore().isAfter(now)) {
            return RiskFactor.of(NAME, POINTS_NOT_YET_VALID, "The site's security certificate is not valid yet");
        }

        int score = 0;
        List<String> notes = new ArrayList<>();

        if (info.notBefore().isAfter(now.minus(NEW_CERT_DAYS, ChronoUnit.DAYS))) {
            score += POINTS_VERY_NEW_CERT;
            notes.add("was issued within the last " + NEW_CERT_DAYS + " days");
        }
        if (info.notAfter().isBefore(now.plus(EXPIRING_SOON_DAYS, ChronoUnit.DAYS))) {
            score += POINTS_EXPIRING_SOON;
            notes.add("expires within " + EXPIRING_SOON_DAYS + " days");
        }

        if (notes.isEmpty()) {
            return RiskFactor.of(NAME, 0, "Valid, trusted certificate that matches the domain");
        }
        return RiskFactor.of(NAME, score, "The certificate is valid but " + String.join(" and ", notes));
    }

    private RiskFactor classifyHandshakeFailure(SSLHandshakeException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateExpiredException) {
                return RiskFactor.of(NAME, POINTS_EXPIRED, "The site's security certificate has expired");
            }
            if (t instanceof CertificateNotYetValidException) {
                return RiskFactor.of(NAME, POINTS_NOT_YET_VALID, "The site's security certificate is not valid yet");
            }
        }
        for (Throwable t = e; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message == null) {
                continue;
            }
            if (message.contains("No subject alternative") || message.contains("No name matching")) {
                return RiskFactor.of(NAME, POINTS_HOST_MISMATCH,
                        "The certificate does not match this domain name");
            }
            if (message.contains("PKIX path building failed")
                    || message.contains("unable to find valid certification path")) {
                return RiskFactor.of(NAME, POINTS_UNTRUSTED,
                        "The certificate is not trusted (self-signed or from an unknown issuer)");
            }
        }
        return RiskFactor.of(NAME, POINTS_OTHER_HANDSHAKE_FAILURE,
                "The site's security certificate could not be verified");
    }

    private boolean messageContains(Throwable t, String text) {
        String message = t.getMessage();
        return message != null && message.toLowerCase(Locale.ROOT).contains(text);
    }
}