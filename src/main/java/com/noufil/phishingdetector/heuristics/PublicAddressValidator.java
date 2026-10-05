package com.noufil.phishingdetector.heuristics;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * SSRF guard. The server must never open a connection to an internal address
 * because a user pasted a URL that points at one (for example
 * http://169.254.169.254/ , the cloud metadata address).
 *
 * A host is only allowed if EVERY address it resolves to is a public address.
 */
public final class PublicAddressValidator {

    /** Thrown when a host resolves to a loopback, private, link-local or reserved address. */
    public static final class BlockedAddressException extends IOException {
        private static final long serialVersionUID = 1L;

        public BlockedAddressException(String message) {
            super(message);
        }
    }

    private PublicAddressValidator() {
    }

    /**
     * Resolves the host once and returns the address to connect to. Connecting to
     * the returned address (not the host name again) closes the DNS-rebinding gap
     * where a second lookup could return a different, internal address.
     */
    public static InetAddress resolvePublic(String host) throws UnknownHostException, BlockedAddressException {
        InetAddress[] addresses = InetAddress.getAllByName(host);
        for (InetAddress address : addresses) {
            if (!isPublic(address)) {
                throw new BlockedAddressException("Host resolves to a non-public address");
            }
        }
        return addresses[0];
    }

    public static boolean isPublic(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()   // 169.254.0.0/16, fe80::/10
                || address.isSiteLocalAddress()   // 10/8, 172.16/12, 192.168/16
                || address.isMulticastAddress()) {
            return false;
        }

        byte[] b = address.getAddress();
        if (b.length == 4) {
            int first = b[0] & 0xFF;
            int second = b[1] & 0xFF;
            int third = b[2] & 0xFF;

            if (first == 0) {
                return false;                                  // 0.0.0.0/8 "this network"
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return false;                                  // 100.64.0.0/10 carrier-grade NAT
            }
            if (first == 192 && second == 0 && third == 0) {
                return false;                                  // 192.0.0.0/24 protocol assignments
            }
            if (first == 198 && (second == 18 || second == 19)) {
                return false;                                  // 198.18.0.0/15 benchmarking
            }
            if (first >= 240) {
                return false;                                  // 240.0.0.0/4 reserved, 255.255.255.255
            }
        } else if ((b[0] & 0xFE) == 0xFC) {
            return false;                                      // fc00::/7 unique local IPv6
        }
        return true;
    }
}