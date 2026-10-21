# TruePulse Backend

Cryptographically verifiable media ingestion pipeline.

## Architectural Security Boundary & Technical Debt Log
- **Ingestion Auth Status (Current):** Protected via shared secret header (x-ingest-secret) over wildcard CORS (*).
- **Scope & Expiration:** Acceptable strictly while the sole client is the local development harness / single-operator test script.
- **Required Gate Before Field Trial / Tester Onboarding:** Must be replaced with Supabase Auth user JWTs accompanied by PostgreSQL Row-Level Security (RLS) policies enforcing uth.uid() = user_id.
