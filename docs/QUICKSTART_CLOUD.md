# Cloud Quick Start

This example sends PostgreSQL findings to an HTTPS webhook using the bundled free packs.

```bash
cp config.yaml.example config.yaml
export DB_PASSWORD='replace-me'
export SIEM_TOKEN='replace-me'
./basecheck-agent --test-siem
./basecheck-agent
```

Configure `config.yaml` with your database host and webhook URL. Use a dedicated least-privilege read-only database account and do not commit secrets.

The bundled PostgreSQL pack has 13 controls. Supabase has 12 preview controls and requires result validation before a finding is treated as confirmed.
