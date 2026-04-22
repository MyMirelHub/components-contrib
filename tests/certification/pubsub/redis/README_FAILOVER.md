# Redis Sentinel Failover Certification Test Report

This directory contains a specialized certification test designed to verify how the Dapr `pubsub.redis` component handles connection pooling during a Redis Sentinel failover. 

Specifically, it demonstrates a known issue where `go-redis` retains stale TCP connections to a demoted master node, resulting in `EOF` or `connection reset by peer` errors when retries are exhausted.

## 🏃 How to Run the Test

You can run the certification test directly using the standard `go test` command. Ensure Docker is running, as the test spins up a containerized Redis Sentinel cluster.

```bash
cd tests/certification
go test -v -count=1 ./pubsub/redis/... -run TestRedisSentinelFailover
```

**Expected Output:**
```
--- FAIL: TestRedisSentinelFailover (96.25s) 
    --- FAIL: TestRedisSentinelFailover/Fails_With_Default_Timeouts (48.11s) 
        --- FAIL: TestRedisSentinelFailover/Fails_With_Default_Timeouts/Fails_With_Default_Timeouts (48.10s) 
    --- PASS: TestRedisSentinelFailover/Passes_With_10s_Timeouts (48.14s) 
        --- PASS: TestRedisSentinelFailover/Passes_With_10s_Timeouts/Passes_With_10s_Timeouts (48.14s) 
FAIL 
FAIL    github.com/dapr/components-contrib/tests/certification/pubsub/redis 96.893s 
```

## 🐳 Docker Compose Architecture

The test relies on a single-container Redis cluster defined in `tests/certification/pubsub/redis/components/sentinel/docker-compose.yml`. 

Unlike standard deployments where the master, replica, and sentinel run in separate containers, this setup runs all three processes inside a **single container** and binds them to `127.0.0.1`. 

### Why a Single Container?
When Dapr runs on the host machine (e.g., macOS or GitHub Actions runners) and connects to a Docker-hosted Sentinel cluster, Sentinel advertises the IP addresses of the master node. If the nodes are in separate containers on a Docker bridge network, Sentinel advertises internal Docker IPs (e.g., `172.18.0.2`) which are unreachable from the host machine. By binding all processes to `127.0.0.1`, Sentinel reliably advertises `127.0.0.1`, allowing Dapr to seamlessly reconnect after a failover.

## 💥 How We Simulate the Fault

To accurately simulate a silent connection drop (similar to what happens behind a cloud load balancer), the test executes the following sequence:

1. **Populate the Pool**: The test publishes 20 messages concurrently. This forces the `go-redis` client inside the Dapr sidecar to open multiple TCP connections to the current Redis master and place them in its idle pool.
2. **Trigger Failover**: The test executes `redis-cli SENTINEL failover mymaster` inside the container to promote the replica to master.
3. **Simulate Proxy Drop**: The test executes `pkill -9 redis-server` inside the container. This forcefully kills the old master process, abruptly closing the TCP sockets that the Dapr sidecar is still holding in its idle pool.
4. **Wait**: The test sleeps for 10 seconds.
5. **Publish**: The test attempts to publish a new message.

## ❌ Why It Fails (Default Behavior)

The first subtest (`Fails_With_Default_Timeouts`) uses `pubsub_fail.yaml`, which relies on the default connection pool settings configured by the Dapr Redis component.

*   **Default `idleTimeout`**: 5 minutes.
*   **Default `maxConnAge`**: Disabled (aged connections are not closed).
*   **Behavior**: When Dapr wakes up to publish the final message, the connections in its pool are only 15 seconds old. Because they haven't reached the 5-minute timeout, the internal `go-redis` reaper hasn't removed them. Dapr grabs a stale connection, attempts to write to it, and the OS immediately rejects it because the socket was closed by the `pkill` command. 
*   **Result**: The component crashes with an `EOF` or `connection reset by peer` error.

## ✅ Why It Passes (10s Mitigation)

The second subtest (`Passes_With_10s_Timeouts`) uses `pubsub_pass.yaml`, which explicitly configures the connection pool timeouts:

```yaml
- name: idleTimeout
  value: "10s" 
- name: maxConnAge
  value: "10s"
```

*   **Behavior**: By the time Dapr wakes up to publish the final message (15 seconds after the failover), the background `go-redis` reaper has identified that the connections have exceeded their 10-second maximum lifespan. The reaper automatically deletes the stale connections. When Dapr attempts to publish, it finds an empty pool, queries Sentinel for the new master address, and dials a fresh connection.
*   **Result**: The component successfully publishes the message without throwing an error.

## 🚀 Suggested Next Steps for Maintainers

This test proves that the default connection pool settings are unsafe for Sentinel deployments. However, the 10s timeout mitigation is a workaround rather than a perfect solution. Maintainers should consider the following paths forward:

### Option 1: Implement the Mitigation (The "Hack")
In `common/component/redis/redis.go` (around line 150), there is a commented-out block designed to automatically inject `10s` defaults when `Failover: true` is detected. Uncommenting this block will mitigate the `EOF` connection thrashing issue for users deploying Dapr with Redis Sentinel by aggressively pruning the connection pool.

### Option 2: Improve Documentation
If automatically changing default connection pool behavior for Sentinel users is deemed too intrusive, Dapr's Redis component documentation should be explicitly updated. Users deploying Redis Sentinel must be instructed to configure `idleTimeout` and `maxConnAge` to low values (e.g., `10s`) to ensure proper failover recovery.

### Option 3: Investigate Robust Cleanup Mechanisms (Ideal)
A more robust, long-term solution should be investigated. Relying on short timeouts causes the pool to constantly churn connections, which is inefficient. Ideally, the component should actively detect Sentinel failover events and explicitly clear/reset the `go-redis` connection pool. While `go-redis` v9 does not currently expose a simple public API to manually clear the pool without closing the entire client, this path warrants further investigation or potentially opening an upstream feature request to `redis/go-redis`.
