# Pulsar + Dapr 1.16.12 RETRY Storm Repro

This repro spins up:

- Pulsar standalone
- Minimal subscriber app (returns HTTP 429 when busy)
- `daprd` pinned to `1.16.12`
- A load generator that rapidly publishes events

## Run

From this folder:

```bash
docker compose up --build
```

## What to watch

In the `daprd` logs you should see repeated lines similar to:

- `Error async processing message ... RETRY status returned from app ... retriable error occurred`

In the `app` logs you should see:

- `app busy: returning 429 to trigger RETRY`

This demonstrates the same failure pattern class as the customer incident:
app-level capacity signaling via RETRY creates retry storms.

## Cleanup

```bash
docker compose down -v
```
