# Security

This document exists because the F1 Telemetry project shipped with a public
Supabase table that had Row-Level Security disabled — a real exposure that
only got caught reactively, via an automated advisory email, weeks after
deploy. The rules below are written so a mistake like that gets caught
*before* it ships, specifically for a security-themed app where getting this
wrong would be especially embarrassing.

## Secrets
- The Google Safe Browsing API key lives only in an environment variable
  (`SAFE_BROWSING_API_KEY` or similar), set in Render's dashboard — never
  hardcoded, never committed to Git, never placed in `application.properties`
  with a real value (the committed file holds only placeholder/empty values).
- `.env` (if used locally) is in `.gitignore` from Phase 0 onward.

## SSRF Prevention (specific to this app)
This app's entire job is handling user-submitted URLs that may be malicious
by design — that makes Server-Side Request Forgery the single most important
risk to design around.
- The server **never fetches or renders the actual content** of a submitted
  URL. All checks operate at the DNS / WHOIS / RDAP / SSL-handshake /
  blacklist-API level only.
- The SSL certificate check opens a TLS handshake to validate the
  certificate — it does not download or process the page body.
- If a future feature ever needs to fetch page content, it must restrict
  outbound requests to public, non-internal IP ranges (block
  `127.0.0.1`, `169.254.x.x`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`,
  and other RFC1918/link-local ranges) and never follow redirects blindly.
  This is out of scope for v1, but must be done at that time if v1's
  boundary is ever crossed.

## Input Validation
- Submitted input is validated as a parseable URL before any check runs.
- Max input length enforced to prevent abuse.
- No submitted input is ever interpolated directly into a shell command,
  file path, or raw SQL/query string (not applicable to v1's stateless
  design, but stays true if persistence is ever added).

## Logging & Data Handling
- Submitted URLs are **not logged** in production in a way that's tied to
  an IP or persisted long-term. Short-lived request logs (e.g. standard
  access logs) are acceptable; a permanent log or database of "what URLs
  did people check" is not — that itself becomes a sensitive dataset
  (it could reveal what services someone almost fell for a scam on).
- No PII is collected. No accounts, no email, no tracking in v1.

## Rate Limiting
- The check endpoint is rate-limited per IP to prevent:
  1. Abuse of free-tier WHOIS/Safe Browsing API quotas by a single actor
  2. The app being used as a bulk URL-scanning tool for unrelated purposes

## Error Handling
- Errors returned to the user are generic and safe ("Couldn't complete this
  check — try again" rather than a raw exception message or stack trace).
- Internal exceptions are logged server-side (without the submitted URL
  itself, per the Logging rule above) for debugging, not shown to the user.

## Dependency Hygiene
- Keep Spring Boot and Maven dependencies reasonably current — security
  patches matter most for a security-themed project specifically, since
  an outdated dependency here would undercut the point of the project.

## What must never happen in this codebase
- API keys or secrets hardcoded anywhere in source, even temporarily "to
  test"
- Disabling SSL/TLS certificate validation anywhere (including in the
  SSL-check heuristic itself — it validates *other* sites' certs, but must
  still make its own outbound calls over valid, verified TLS)
- Fetching or rendering arbitrary user-submitted URL content server-side
- Logging raw submitted URLs tied to a requester in a persistent store
- Committing `.env` or any file containing a real credential
