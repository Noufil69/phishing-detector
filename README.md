# Fake-URL / Phishing Detector

A web app where you paste a URL you're unsure about and get back a risk
score (Low / Medium / High) with a plain-English breakdown of why — built in
Java + Spring Boot. See `docs/TRD.md`, `docs/ARCHITECTURE.md`,
`docs/IMPLEMENTATION_PLAN.md`, and `docs/SECURITY.md` for the full plan.

## Status

Phase 0 (project setup) — skeleton boots, no real heuristics wired in yet.

## Requirements

- Java 21
- Maven 3.9+ (or just use the included `mvnw` wrapper — none bundled yet,
  use your local `mvn` for now)

## Running locally

```bash
cp .env.example .env
# edit .env if you have a Safe Browsing API key yet (not needed for Phase 0)

mvn spring-boot:run
```

Then visit: http://localhost:8080/api/health — should return
`{"status":"ok","service":"phishing-detector"}`.

## Project structure

```
/src/main/java/.../phishingdetector
  /controller      # REST endpoints
  /service         # Orchestration + aggregation
  /heuristics      # HeuristicCheck interface + implementations
  /model           # RiskFactor, RiskScore, RiskLevel
  /config          # Rate limiting, external API client config
  /exception       # Global error handling
/src/main/resources
  /templates       # Thymeleaf frontend
  /static          # CSS/JS
  application.properties
/docs              # TRD, ARCHITECTURE, IMPLEMENTATION_PLAN, SECURITY
```
