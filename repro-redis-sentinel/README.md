# Redis Sentinel Failover Repro

This directory contains a reproduction environment and test script for investigating `EOF` errors encountered during Redis Sentinel failovers when using the Dapr `pubsub.redis` component.

## Background

When a Redis Sentinel failover occurs (e.g., due to a hiccup on the master node), Sentinel promotes a replica to be the new master. However, Dapr clients might still hold open TCP connections to the old master in their connection pool. 

If a Dapr sidecar attempts to publish a message using one of these stale connections, the underlying `go-redis` client library throws an error (often `EOF` or `connection reset by peer`), as the socket has been closed by the old master or is no longer accepting writes.

This reproduction verifies the issue and demonstrates how tuning the connection pool metadata properties (`maxConnAge`, `idleTimeout`, `minIdleConns`) can mitigate these stale connection errors by aggressively recycling the connection pool.

## Prerequisites

- Docker and Docker Compose
- Go 1.23+

## Setup

1. **Start the Redis Sentinel Cluster**
   This spins up a 3-node cluster: one master, one replica, and one sentinel node using Redis 7.4 (which uses the exact same Dapr `v9` client code path as Redis 8).
   
   ```bash
   docker-compose up -d
   ```

## Reproducing the Error

To reliably reproduce the error, we configure Dapr to disable its built-in retries (`redisMaxRetries: "0"`). This ensures the raw `EOF` error surfaces immediately instead of being silently retried by `go-redis`.

1. **Run the Go script in a background terminal:**
   This script initializes the Dapr Redis pubsub component, publishes a message, and then waits 15 seconds before publishing a second message.
   
   ```bash
   docker run --rm --network repro-redis-sentinel_default -v $PWD/..:/components-contrib -w /components-contrib/repro-redis-sentinel golang:1.24 bash -c "go build -o test_repro main.go && ./test_repro"
   ```

2. **Trigger a Sentinel Failover:**
   While the Go script is waiting during its 15-second sleep window, open another terminal and force Sentinel to failover to the replica:
   
   ```bash
   docker run --rm --network repro-redis-sentinel_default bitnami/redis:latest redis-cli -h redis-sentinel -p 26379 SENTINEL failover mymaster
   ```

3. **Observe the Error:**
   In the output of the Go script, you will see Sentinel detect the new master, but the second publish attempt will fail with an `EOF` error because it tried to reuse the stale connection from the pool.

   ```text
   Initializing...
   redis: 2026/04/15 18:18:36 sentinel.go:661: sentinel: new master="mymaster" addr="172.19.0.2:6379"
   Init finished, err: <nil>
   Successfully initialized Redis pubsub with Sentinel.
   First publish succeeded
   Waiting 15 seconds to simulate idle connection and allow failover...
   
   --- REPRODUCED ERROR ---
   Second publish failed: redis streams: error from publish: EOF
   ------------------------
   ```

## The Mitigation

To fix this, we can tune the Dapr component's connection pool settings to aggressively close connections that have been sitting idle. 

By adding the following properties to your Dapr component YAML (and removing the disabled retries):

```yaml
metadata:
  - name: maxConnAge
    value: "10s"
  - name: idleTimeout
    value: "10s"
  - name: minIdleConns
    value: "0"
```

### Results with Mitigation
When the `idleTimeout` and `maxConnAge` are set shorter than the time the connection sits idle (e.g., our 15-second wait), the `go-redis` client actively prunes the stale connection from the pool. 

When the second publish request fires, the client sees no available idle connections, asks Sentinel for the current master address, creates a fresh connection to the newly promoted master, and successfully publishes the message without hitting the `EOF` error.

```text
First publish succeeded
Waiting 15 seconds to simulate idle connection and allow failover...
Second publish succeeded
```