# Technical Requirements Document

## 1. Project Overview
A web application where a user pastes a URL they're unsure about and receives a
risk score (Low / Medium / High) with a plain-English breakdown of why. Built
to demonstrate backend engineering in a language/stack (Java + Spring Boot)
different from the rest of the portfolio, and to show applied security
thinking rather than just CRUD.

## 2. Technical Goals
- Manual, on-demand checking only — no automatic/background scanning.
- Each risk factor is explained, not just scored (so the output is useful,
  not a black box).
- Runs entirely on free-tier services (no recurring cost).
- Demonstrates clean OOP design (interfaces, polymorphism) over a quick hack.

## 3. Proposed Tech Stack
- Backend: Java 17, Spring Boot 3.x, Maven
- Frontend: Simple server-rendered page (Thymeleaf) or a static HTML + fetch()
  page calling a REST endpoint — decide in Phase 8, not before.
- Hosting: Render (free tier)
- No database for v1 — each check is stateless and computed fresh per
  request. (A DB can be added later for a "recent checks" history feature —
  out of scope for v1.)
- External services: Google Safe Browsing API (free tier), RDAP/WHOIS lookup,
  Java's built-in SSL handshake for certificate checks.

## 4. Functional Requirements

### URL Submission
- User can paste any URL into a text field and submit it.
- System rejects empty input and obviously malformed input (not a parseable
  URL) with a clear message before running any checks.

### Risk Analysis
- System runs all five heuristic checks against the submitted URL:
  1. Structural red flags (IP-literal host, excessive subdomains, `@` in URL,
     known shortener domains, suspicious TLDs)
  2. Typosquat detection (edit-distance against a known-brand domain list)
  3. SSL certificate validity (present, not expired, hostname match)
  4. Domain age (via WHOIS/RDAP — newly registered domains score higher risk)
  5. Google Safe Browsing blacklist cross-check
- Each check returns a partial score + a human-readable reason, even when it
  finds nothing wrong (e.g. "Domain registered 6 years ago — not a risk
  factor").
- If an individual check fails (API down, timeout, lookup error), the overall
  analysis still completes using the remaining checks, with that one check
  shown as "unavailable" rather than crashing the whole request.

### Results Display
- User sees: overall risk level (Low/Medium/High), a numeric or visual score,
  and the per-check breakdown with reasons.

## 5. Non-Functional Requirements
- Respond within a reasonable time despite external API calls — each external
  call (WHOIS, Safe Browsing, SSL handshake) must have an explicit timeout
  (e.g. 3-5 seconds) so one slow service doesn't hang the whole request.
- No submitted URL is persisted or logged beyond what's needed to serve that
  one request (see SECURITY.md).
- Mobile-responsive single page.
- Clear loading state while checks run (this can take a few seconds due to
  external lookups).

## 6. Integrations
- **Google Safe Browsing API** — blacklist cross-check. Free tier, requires
  an API key (env var, see SECURITY.md).
- **RDAP/WHOIS** — domain registration date lookup. Prefer RDAP (structured,
  no key needed) over scraping raw WHOIS text.
- **Java SSL/TLS handshake** (`javax.net.ssl`) — certificate presence,
  expiry, and hostname validation. No external service needed for this one.
- **Static brand/domain list** — a maintained JSON or properties file of
  common phishing targets (PayPal, major banks, Microsoft, Google, etc.) for
  the typosquat check. Starts small, can grow over time.

## 7. Constraints
- Secrets (Safe Browsing API key) live only in environment variables — never
  hardcoded, never committed.
- The server never fetches or renders the actual page content of a
  submitted URL — all checks operate at the DNS/WHOIS/SSL/metadata level
  only. This is a deliberate SSRF-prevention boundary (see SECURITY.md).
- The analysis endpoint is rate-limited per IP to avoid burning through
  WHOIS/Safe Browsing free-tier quotas from abuse.
- No user accounts, no login, no persistent user data in v1.

## 8. Definition of Done
- All five heuristic checks implemented and contributing to the score.
- Graceful degradation confirmed (kill one external dependency, verify the
  app still returns a partial result instead of crashing).
- Deployed and reachable on Render.
- Linked from the portfolio site (external link, not a subdomain).
- README explains what it does, how to run it locally, and its limitations
  (e.g. "not a substitute for a real security product — a portfolio
  demonstration of the underlying techniques").
