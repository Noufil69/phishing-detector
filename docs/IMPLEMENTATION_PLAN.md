# Implementation Plan

## Project Rule
Build one phase at a time. Do not start the next phase until the current
phase passes its verification checks. Read TRD.md and ARCHITECTURE.md before
starting Phase 0.

## Phase 0 — Project Setup
Tasks:
- Generate Spring Boot project (Spring Initializr): Web, Validation
  dependencies
- Set up folder structure per ARCHITECTURE.md
- Add `.env` / `application.properties` template with placeholder keys
  (never real values committed)
- Add `.gitignore` covering `.env`, `target/`, IDE files
- Confirm app runs locally with a placeholder "hello" endpoint

Deliverable: App runs locally with no setup errors.
Verify: Fresh clone + documented commands gets the app running.

## Phase 1 — Core Domain Model
Tasks:
- Create `RiskFactor`, `RiskScore`, `RiskLevel` model classes
- Create `HeuristicCheck` interface
- Create `ScoreAggregator` with a placeholder scoring formula
- Create `UrlCheckService` that can run an empty list of checks and return a
  valid (trivial) `RiskScore`

Deliverable: The skeleton compiles and `UrlCheckService.analyze(url)` returns
a `RiskScore` object end-to-end, even with zero real heuristics wired in yet.
Verify: Unit test confirms `analyze()` returns a non-null `RiskScore` with
`RiskLevel.LOW` when no checks are registered.

## Phase 2 — Structural Heuristic
Tasks:
- Implement `StructuralHeuristic`: IP-literal host detection, subdomain
  count threshold, `@` symbol in URL, known shortener domain list,
  suspicious/uncommon TLD check
- Register it with `UrlCheckService`
- Unit tests covering each red flag individually and a clean URL

Deliverable: Submitting a URL returns a real structural risk factor with a
reason string.
Verify: Known-bad test URLs (IP-literal, shortener) score higher than a
clean URL like `https://example.com`.

## Phase 3 — Typosquat Heuristic
Tasks:
- Build the static brand/domain list (start with ~15-20 common targets)
- Implement edit-distance comparison (Levenshtein) between the submitted
  domain and the brand list
- Tune the distance threshold to avoid false positives on legitimately
  similar but unrelated domains

Deliverable: A near-miss domain (e.g. `paypa1.com`) scores as high risk;
`paypal.com` itself scores as low/no risk from this check.
Verify: Test against a handful of real-world typosquat examples and a few
legitimate lookalike-but-unrelated domains to check the false-positive rate.

## Phase 4 — SSL Certificate Heuristic
Tasks:
- Implement `SslCertHeuristic`: open a TLS handshake to the host, check
  certificate presence, expiry, and hostname match
- Handle non-HTTPS URLs explicitly (missing SSL entirely is itself a signal)
- Timeout handling for unreachable hosts

Deliverable: Expired/self-signed/mismatched certs are flagged; a valid cert
is not.
Verify: Test against a known-expired-cert test domain and a known-good one.

## Phase 5 — Domain Age Heuristic
Tasks:
- Integrate RDAP lookup for domain registration date
- Implement `DomainAgeHeuristic`: score inversely to domain age (very new =
  higher risk)
- Timeout + fallback handling when RDAP has no data for a TLD

Deliverable: A newly-registered test domain scores higher risk than an
established one.
Verify: Test against a domain known to be decades old and confirm low score
from this specific check.

## Phase 6 — Google Safe Browsing Integration
Tasks:
- Register for a Safe Browsing API key, store in env var only
- Implement `SafeBrowsingHeuristic`: cross-check the URL against the
  blacklist API
- Handle API errors/timeouts as "unavailable" rather than crashing

Deliverable: A known Safe Browsing test URL (Google publishes official test
URLs for this) is correctly flagged.
Verify: Test with Google's published test-malware URL and a clean URL.

## Phase 7 — Score Aggregation
Tasks:
- Finalize the real scoring formula across all five factors in
  `ScoreAggregator`
- Map total score to `RiskLevel` (Low/Medium/High) with documented
  thresholds
- Handle the "some checks unavailable" case in the final score fairly
  (don't let 2 failed checks silently make a URL look safer than it is)

Deliverable: End-to-end request through all five checks returns a coherent,
explainable final score.
Verify: Manually test a known-safe URL, a known-phishing-style test URL, and
a URL with one external dependency intentionally broken (e.g. revoke the
Safe Browsing key temporarily) to confirm graceful degradation.

## Phase 8 — Frontend
Tasks:
- Build the single-page UI: URL input, submit, loading state, results
  breakdown display
- Responsive layout (mobile + desktop)
- Clear visual distinction between Low/Medium/High risk results

Deliverable: A user can paste a URL and see a readable, explained result
without touching the API directly.
Verify: Test on mobile width and desktop width; test the loading state is
visible during the few seconds the checks take.

## Phase 9 — Production Readiness
Tasks:
- Add per-IP rate limiting on the check endpoint
- Confirm no submitted URLs are logged in production (see SECURITY.md)
- Add global error handling (no stack traces shown to users)
- Deploy to Render, configure env vars there (never in code)
- Full pass against SECURITY.md checklist

Deliverable: Production-ready MVP, live on Render.
Verify:
- Rate limit actually triggers on rapid repeated requests
- Production logs confirmed clean of submitted URLs
- Full manual run-through of all 5 heuristics against real test URLs on the
  live deployment

## Out of Scope for v1
- User accounts / login
- Check history / database persistence
- Browser extension or automatic scanning
- Caching of repeated domain lookups
- Parallelized heuristic execution (sequential is fine at this scale)
