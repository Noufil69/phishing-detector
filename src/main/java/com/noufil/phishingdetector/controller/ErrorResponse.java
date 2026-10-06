package com.noufil.phishingdetector.controller;

/** A problem with the request, in plain English: {"error": "..."}. */
public record ErrorResponse(String error) {
}