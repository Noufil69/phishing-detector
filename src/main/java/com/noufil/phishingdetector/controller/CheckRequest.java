package com.noufil.phishingdetector.controller;

/**
 * What the caller sends to POST /api/check: {"url": "https://example.com"}.
 *
 * A plain class with a setter (not a record), because that is the safest shape for
 * the JSON reader to fill in, whatever its version.
 */
public class CheckRequest {

    private String url;

    public CheckRequest() {
    }

    public CheckRequest(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}