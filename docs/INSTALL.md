# Installation

Download the archive and matching SHA-256 file for your platform from [GitHub Releases](https://github.com/baselabs-io/basecheck-agent/releases).

## macOS and Linux

```bash
shasum -a 256 -c basecheck-agent-linux-amd64.tar.gz.sha256
tar -xzf basecheck-agent-linux-amd64.tar.gz
cd basecheck-agent
cp config.yaml.example config.yaml
./basecheck-agent --version
```

## Windows

```powershell
Get-FileHash .\basecheck-agent-windows-amd64.zip -Algorithm SHA256
Expand-Archive .\basecheck-agent-windows-amd64.zip
cd .\basecheck-agent
copy config.yaml.example config.yaml
.\basecheck-agent.exe --version
```

Compare the Windows hash with the matching `.sha256` file.

## Configure and Run

The public archive contains six free control packs in `control-sets/`. Configure a database, a generic HTTP/webhook or syslog destination, and run:

```bash
./basecheck-agent --test-siem
./basecheck-agent
```

Use a dedicated least-privilege read-only account and environment variables for secrets. `--test-siem` checks only output delivery.

The same agent can use separately distributed paid packs with a valid entitlement. Paid packs are not included in this archive.
