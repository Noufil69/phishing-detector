package com.noufil.phishingdetector.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    void invalidUrlBecomesItsOwnMessage() {
        ErrorResponse response = handler.invalidUrl(new InvalidUrlException("Please enter a URL to check."));
        assertEquals("Please enter a URL to check.", response.error());
    }

    @Test
    void unreadableBodyGetsAFixedHelpfulMessage() {
        ErrorResponse response = handler.unreadableBody();
        assertTrue(response.error().contains("\"url\""));
    }
}