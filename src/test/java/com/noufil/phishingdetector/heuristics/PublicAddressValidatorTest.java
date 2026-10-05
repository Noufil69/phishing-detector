package com.noufil.phishingdetector.heuristics;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.PublicAddressValidator.BlockedAddressException;

class PublicAddressValidatorTest {

    // InetAddress.getByName with an IP literal does not do any DNS lookup.
    private static boolean isPublic(String literal) throws Exception {
        return PublicAddressValidator.isPublic(InetAddress.getByName(literal));
    }

    @Test
    void ordinaryPublicAddressesAreAllowed() throws Exception {
        assertTrue(isPublic("8.8.8.8"));
        assertTrue(isPublic("1.1.1.1"));
        assertTrue(isPublic("93.184.216.34"));
        assertTrue(isPublic("2606:4700:4700::1111"));
    }

    @Test
    void loopbackIsBlocked() throws Exception {
        assertFalse(isPublic("127.0.0.1"));
        assertFalse(isPublic("127.5.5.5"));
        assertFalse(isPublic("::1"));
    }

    @Test
    void privateRangesAreBlocked() throws Exception {
        assertFalse(isPublic("10.0.0.5"));
        assertFalse(isPublic("172.16.0.1"));
        assertFalse(isPublic("172.31.255.255"));
        assertFalse(isPublic("192.168.1.1"));
    }

    @Test
    void edgeOfPrivate172RangeIsHandledCorrectly() throws Exception {
        assertTrue(isPublic("172.15.0.1"));
        assertTrue(isPublic("172.32.0.1"));
    }

    @Test
    void cloudMetadataAddressIsBlocked() throws Exception {
        assertFalse(isPublic("169.254.169.254"));
    }

    @Test
    void carrierGradeNatIsBlocked() throws Exception {
        assertFalse(isPublic("100.64.0.1"));
        assertFalse(isPublic("100.127.255.255"));
        assertTrue(isPublic("100.128.0.1"));
    }

    @Test
    void unspecifiedAndReservedAreBlocked() throws Exception {
        assertFalse(isPublic("0.0.0.0"));
        assertFalse(isPublic("0.1.2.3"));
        assertFalse(isPublic("240.0.0.1"));
        assertFalse(isPublic("255.255.255.255"));
        assertFalse(isPublic("224.0.0.1"));
    }

    @Test
    void ipv6PrivateRangesAreBlocked() throws Exception {
        assertFalse(isPublic("fc00::1"));
        assertFalse(isPublic("fd12:3456:789a::1"));
        assertFalse(isPublic("fe80::1"));
    }

    @Test
    void ipv4MappedLoopbackIsBlocked() throws Exception {
        assertFalse(isPublic("::ffff:127.0.0.1"));
    }

    @Test
    void resolvePublicRejectsLoopbackLiteral() {
        assertThrows(BlockedAddressException.class,
                () -> PublicAddressValidator.resolvePublic("127.0.0.1"));
    }

    @Test
    void resolvePublicRejectsMetadataLiteral() {
        assertThrows(BlockedAddressException.class,
                () -> PublicAddressValidator.resolvePublic("169.254.169.254"));
    }

    @Test
    void resolvePublicRejectsLocalhostName() {
        assertThrows(BlockedAddressException.class,
                () -> PublicAddressValidator.resolvePublic("localhost"));
    }

    @Test
    void resolvePublicReturnsPublicLiteral() throws Exception {
        assertEquals("8.8.8.8", PublicAddressValidator.resolvePublic("8.8.8.8").getHostAddress());
    }
}