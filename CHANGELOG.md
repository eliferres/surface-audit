# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added

- `surface-audit run surfaces.json`, which checks every surface in a config file and writes a dated report to `reports/`, one row per rule with the exact request and the answer that decided it.
- Header rules H1 to H6, graded pass, warn or fail: HSTS max-age, a Content-Security-Policy (with `'unsafe-inline'` or `'unsafe-eval'` for scripts as a warning), framing protection, nosniff, a referrer policy and a permissions policy.
- H7: a plain http request to each host must be redirected to https.
- T1 and T2: the tables of a PostgREST or Supabase database, listed from its OpenAPI description or the config, each asked for one row with the public key and no session; a table that answers rows fails unless the config lists it in `public_tables`.
- R1: each URL under `must_refuse` must answer 401 or 403 to a request with no session.
- S1: every file in the built site folder is scanned for a service-role token, provider keys and private keys; the report names the file and the shape, never the value.
- G1: git must track no `.env` file (templates aside) and no `.pem`, `.key`, `.p12` or `.pfx` file.
- A config whose key carries the `service_role` claim is refused before any request is sent.
- `--json` output for CI, `--out` to choose the report folder, and exit codes 0 for clean, 1 for findings, 2 for a configuration error or a surface that did not answer.
