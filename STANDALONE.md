# Standalone Deployment

This guide covers the free standalone configuration. It runs the six bundled free packs locally and writes findings to JSON or sends them to generic HTTP/webhook or syslog destinations.

The same agent can run separately distributed paid packs with a valid entitlement. Those packs and their configuration are not included in the public archive.

## Install

Download an archive from [GitHub Releases](https://github.com/baselabs-io/basecheck-agent/releases), verify its checksum, extract it, and copy `config.yaml.example` to `config.yaml`.

```bash
shasum -a 256 -c basecheck-agent-darwin-arm64.tar.gz.sha256
tar -xzf basecheck-agent-darwin-arm64.tar.gz
cd basecheck-agent
cp config.yaml.example config.yaml
```

## Configure and Run

Use dedicated least-privilege read-only database credentials. Configure a generic HTTP/webhook or syslog destination, then run:

```bash
./basecheck-agent --test-siem
./basecheck-agent
```

`--test-siem` validates only the configured output destination.

## Free Pack Scope

| Database | Controls | Status |
| --- | ---: | --- |
| SQL Server | 14 | Supported |
| Oracle | 14 | Supported; Oracle Instant Client required |
| PostgreSQL | 13 | Supported |
| Supabase | 12 | Preview |
| SQLite | 5 baseline + discovery | Supported |

The standalone agent requires no inbound network connection and does not install software on the database server.
