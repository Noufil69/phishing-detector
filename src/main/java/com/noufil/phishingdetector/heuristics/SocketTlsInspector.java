package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Real TlsInspector: opens a TCP connection and performs a TLS handshake.
 *
 * Safety rules (see docs/SECURITY.md):
 *  - Port is fixed at 443. The user can never choose a port, so this cannot be
 *    used to port-scan other machines.
 *  - The host is resolved once and checked against PublicAddressValidator; the
 *    connection then goes to that exact address.
 *  - Connect and read both have a hard timeout.
 *  - Certificate validation is the JVM default: trusted chain, validity dates and
 *    host name match. It is never disabled.
 *  - Only the handshake happens. No HTTP request is sent, no page is fetched.
 */
@Component
public class SocketTlsInspector implements TlsInspector {

    private static final int PORT = 443;

    private final int timeoutMs;
    private final SSLSocketFactory socketFactory;

    public SocketTlsInspector(@Value("${heuristics.http-timeout-ms:4000}") int timeoutMs) {
        this.timeoutMs = timeoutMs;
        this.socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    @Override
    public CertificateInfo inspect(String host) throws IOException {
        InetAddress address = PublicAddressValidator.resolvePublic(host);

        try (Socket plain = new Socket()) {
            plain.connect(new InetSocketAddress(address, PORT), timeoutMs);
            plain.setSoTimeout(timeoutMs);

            // Layering TLS over the already-connected socket lets us connect to the
            // vetted IP while still sending the host name for SNI and verification.
            try (SSLSocket ssl = (SSLSocket) socketFactory.createSocket(plain, host, PORT, true)) {
                SSLParameters params = ssl.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS"); // enforce host name match
                ssl.setSSLParameters(params);

                ssl.startHandshake();

                Certificate[] chain = ssl.getSession().getPeerCertificates();
                X509Certificate leaf = (X509Certificate) chain[0];
                return new CertificateInfo(
                        leaf.getNotBefore().toInstant(),
                        leaf.getNotAfter().toInstant());
            }
        }
    }
}