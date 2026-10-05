package com.noufil.phishingdetector.heuristics;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;

/**
 * Only tests the safety rule that can be checked offline: internal addresses are
 * refused BEFORE any connection is attempted. Real handshakes are not tested here
 * because unit tests must not depend on the internet.
 */
class SocketTlsInspectorTest {

    private final SocketTlsInspector inspector = new SocketTlsInspector(1000);

    @Test
    void refusesLoopbackAddress() {
        assertThrows(BlockedAddressException.class, () -> inspector.inspect("127.0.0.1"));
    }

    @Test
    void refusesCloudMetadataAddress() {
        assertThrows(BlockedAddressException.class, () -> inspector.inspect("169.254.169.254"));
    }

    @Test
    void refusesPrivateNetworkAddress() {
        assertThrows(BlockedAddressException.class, () -> inspector.inspect("192.168.0.10"));
    }

    @Test
    void refusesLocalhostName() {
        assertThrows(BlockedAddressException.class, () -> inspector.inspect("localhost"));
    }
}