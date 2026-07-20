# BaseCheck Agent

Source-available database security scanner with generic HTTP/webhook, syslog, and JSON output.

BaseCheck Agent runs locally with dedicated least-privilege database credentials and checks database security configuration.

The same agent supports free and paid control packs. This repository and its public release bundle six free packs. Paid packs are distributed separately and require a valid entitlement.

## Bundled Free Packs

| Database | Controls | Status |
| --- | ---: | --- |
| SQL Server | 14 | Supported |
| Oracle | 14 | Supported; Oracle Instant Client required |
| PostgreSQL | 13 | Supported |
| Supabase | 12 | Preview |
| SQLite | 5 baseline + discovery | Supported |

## Quick Start

Download the archive for your platform from [GitHub Releases](https://github.com/baselabs-io/basecheck-agent/releases), extract it, and copy the example configuration.

```bash
tar -xzf basecheck-agent-darwin-arm64.tar.gz
cd basecheck-agent
cp config.yaml.example config.yaml
```

Configure a database and an HTTP/webhook or syslog destination, then run:

```bash
./basecheck-agent --test-siem
./basecheck-agent
```

`--test-siem` sends a test event to the configured destination. It does not test database credentials or run controls.

## Output

The agent can write findings to local JSON files or send versioned JSON events to generic HTTP/webhook endpoints or syslog over TCP or UDP. These are generic destinations, not native SIEM connectors.

The bundled configuration runs local free packs. The universal agent can also use separately distributed paid packs with a valid entitlement; paid-pack and platform configuration are not included here.

## Requirements

- Network access from the agent host to the target database.
- Dedicated least-privilege, read-only database credentials.
- Oracle Instant Client for Oracle targets.
- Network access to the configured output destination when using HTTP/webhook or syslog output.

The agent does not install software on the database server.

For full setup details, see [installation](docs/INSTALL.md), [standalone deployment](STANDALONE.md), [cloud databases](docs/CLOUD_DATABASES.md), and the [local SQLite demo](examples/siem-demo/README.md).

## License

BaseCheck Agent is licensed under the [Business Source License 1.1](LICENSE). It is source-available, not OSI-approved open source. See [LICENSE](LICENSE) for the full terms.

## Security and Feedback

Report vulnerabilities to [info@basecheck.ai](mailto:info@basecheck.ai). Do not disclose suspected vulnerabilities in a public issue.
