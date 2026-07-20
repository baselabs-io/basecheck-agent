# Local SQLite to SIEM Demo

This demo creates an intentionally unsafe SQLite database, starts a local HTTP
receiver, runs the real agent, and prints the received SIEM events.

Run it from the BaseCheck Agent directory after building the binary:

```bash
go build -o basecheck-agent ./cmd/agent
bash examples/siem-demo/run.sh
```

The demo uses HTTP only on `127.0.0.1` and sets `security.allow_http: true` for
that purpose. Do not use this setting for a production SIEM destination.

The fixture intentionally has foreign-key enforcement disabled, an invalid
foreign-key row, and unsafe journal mode. Each run uses a fresh temporary
directory, so it cannot reuse or erase a normal agent queue. The script prints
the delivered `basecheck.siem.v1` events and the temporary directory path.
