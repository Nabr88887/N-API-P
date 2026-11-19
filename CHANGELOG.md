# Changelog

All notable project changes are recorded here.

## [Unreleased]

- Improve repository discoverability and public documentation.
- Add an interactive architecture diagram and GitHub social preview.
- Add GitHub Pages, citation metadata, contribution guidance, and security policy.

## [0.1.0] - 2026-11-19

Initial public graduation-design baseline.

### Added

- OpenAI-compatible model listing and Chat Completions data plane.
- Non-streaming, SSE, and tool-call handling.
- Invite-only accounts and role-based administration.
- Personal API keys and team-owned service-account keys.
- Model allowlist, rate limits, usage attribution, and price snapshots.
- Encrypted request/response audit with bounded retention.
- Administrator reauthentication and governed audit review.
- Prometheus metrics, health checks, and container deployment examples.
- Synthetic local demo with generated credentials and a NewAPI-compatible mock.

### Security

- Upstream NewAPI credentials remain server-side.
- Full downstream API keys are displayed once and are not stored recoverably.
- New traffic fails closed when required audit persistence is unavailable.
- Raw audit content is excluded from metadata backups.
