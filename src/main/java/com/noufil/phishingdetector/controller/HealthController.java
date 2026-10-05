package com.noufil.phishingdetector.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Placeholder endpoint for Phase 0 — confirms the app boots and routes work
 * before any real heuristic logic exists. Safe to delete once
 * UrlCheckController (Phase 1+) is in place and the app has a real root
 * route via the Thymeleaf frontend (Phase 8).
 */
@RestController
public class HealthController {

    @GetMapping("/api/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "service", "phishing-detector");
    }

}
