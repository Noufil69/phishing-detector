package com.noufil.phishingdetector.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns request problems into a short, plain JSON message instead of a stack trace
 * or a generic error page. Phase 9 adds the catch-all handler for unexpected errors.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(InvalidUrlException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse invalidUrl(InvalidUrlException e) {
        return new ErrorResponse(e.getMessage());
    }

    /** The body was missing or was not JSON like {"url": "..."}. Nothing from it is echoed back. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse unreadableBody() {
        return new ErrorResponse("Send JSON like {\"url\": \"https://example.com\"}.");
    }
}