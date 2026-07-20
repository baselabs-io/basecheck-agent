# Cloud Databases

BaseCheck Agent can run against supported cloud databases when the agent host can reach the database and the bundled controls can query the required metadata.

| Target | Free controls | Notes |
| --- | ---: | --- |
| Managed PostgreSQL | 13 | Dedicated read-only account and TLS |
| Supabase | 12 | Preview; validate results against your project |
| Managed SQL Server | 14 | Dedicated read-only account and TLS |
| Managed Oracle | 14 | Oracle Instant Client on the agent host |

Use the bundled free packs with `control_sets.source: local`. Findings can be written to local JSON or sent to generic HTTP/webhook or syslog destinations.

Use TLS, dedicated least-privilege accounts, and environment variables for credentials. Do not use administrator credentials.

The same agent can run separately distributed paid packs with a valid entitlement; they are not included in the public archive.
