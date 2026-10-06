package com.noufil.phishingdetector.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.noufil.phishingdetector.heuristics.HostExtractor;
import com.noufil.phishingdetector.model.RiskScore;
import com.noufil.phishingdetector.service.UrlCheckService;

/**
 * POST /api/check with {"url": "..."} runs every heuristic and returns the verdict.
 *
 * POST, not GET, so the pasted URL never ends up in a query string, which servers and
 * proxies like to write into their logs. Nothing here logs or stores the URL.
 */
@RestController
@RequestMapping("/api")
public class UrlCheckController {

    private final UrlCheckService service;

    public UrlCheckController(UrlCheckService service) {
        this.service = service;
    }

    @PostMapping("/check")
    public CheckResponse check(@RequestBody CheckRequest request) {
        String url = UrlInputValidator.validate(request == null ? null : request.getUrl());
        RiskScore result = service.analyze(url);
        String host = HostExtractor.extractHost(url).orElse("");
        return CheckResponse.from(result, host);
    }
}