/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package redis

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	kitlogger "github.com/dapr/kit/logger"
)

type poolRefreshingClient struct {
	mu                  sync.RWMutex
	client              RedisClient
	newClientFn         func() (RedisClient, error)
	logger              *kitlogger.Logger
	validateBeforeUse   bool
	healthCheckInterval time.Duration
	lastHealthCheckUnix atomic.Int64
	refreshing          atomic.Bool
	closed              atomic.Bool
	monitorStop         context.CancelFunc
}

func newPoolRefreshingClient(client RedisClient, newClientFn func() (RedisClient, error), logger *kitlogger.Logger, validateBeforeUse bool, healthCheckInterval time.Duration) RedisClient {
	return &poolRefreshingClient{
		client:              client,
		newClientFn:         newClientFn,
		logger:              logger,
		validateBeforeUse:   validateBeforeUse,
		healthCheckInterval: healthCheckInterval,
	}
}

func (c *poolRefreshingClient) startMonitors(useV9 bool, settings *Settings) {
	ctx, cancel := context.WithCancel(context.Background())
	c.monitorStop = cancel

	if settings.Failover && settings.RefreshPoolOnSentinelSwitch {
		if useV9 {
			go runSentinelSwitchMonitorV9(ctx, settings, c.logger, c.refreshPool)
		} else {
			go runSentinelSwitchMonitorV8(ctx, settings, c.logger, c.refreshPool)
		}
	}

	if settings.PoolRefreshInterval > 0 {
		go c.runPeriodicRefreshMonitor(ctx, time.Duration(settings.PoolRefreshInterval))
	}
}

func (c *poolRefreshingClient) getClient() RedisClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

func (c *poolRefreshingClient) refreshPool(reason string) {
	if c.closed.Load() {
		return
	}
	if !c.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer c.refreshing.Store(false)

	newClient, refreshErr := c.newClientFn()
	if refreshErr != nil {
		if c.logger != nil {
			(*c.logger).Warnf("redis client: failed to refresh connection pool (%s): %v", reason, refreshErr)
		}
		return
	}

	c.mu.Lock()
	oldClient := c.client
	c.client = newClient
	c.mu.Unlock()

	if oldClient != nil {
		_ = oldClient.Close()
	}

	if c.logger != nil {
		(*c.logger).Infof("redis client: refreshed connection pool (%s)", reason)
	}
}

func (c *poolRefreshingClient) ensureLiveConnection(ctx context.Context) error {
	if !c.validateBeforeUse || c.closed.Load() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if c.healthCheckInterval > 0 {
		last := c.lastHealthCheckUnix.Load()
		if last != 0 && time.Since(time.Unix(0, last)) < c.healthCheckInterval {
			return nil
		}
	}

	_, err := c.getClient().PingResult(ctx)
	if err == nil {
		c.lastHealthCheckUnix.Store(time.Now().UnixNano())
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	c.refreshPool("pre-command health check failed")
	_, err = c.getClient().PingResult(ctx)
	if err == nil {
		c.lastHealthCheckUnix.Store(time.Now().UnixNano())
	}
	return err
}

func (c *poolRefreshingClient) runPeriodicRefreshMonitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshPool("periodic interval")
		}
	}
}

func (c *poolRefreshingClient) IsNilValueError(err error) bool {
	return c.getClient().IsNilValueError(err)
}

func (c *poolRefreshingClient) Context() context.Context {
	return c.getClient().Context()
}

func (c *poolRefreshingClient) DoRead(ctx context.Context, args ...interface{}) (interface{}, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err
	}
	return c.getClient().DoRead(ctx, args...)
}

func (c *poolRefreshingClient) DoWrite(ctx context.Context, args ...interface{}) error {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return err
	}
	return c.getClient().DoWrite(ctx, args...)
}

func (c *poolRefreshingClient) Del(ctx context.Context, keys ...string) error {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return err
	}
	return c.getClient().Del(ctx, keys...)
}

func (c *poolRefreshingClient) Get(ctx context.Context, key string) (string, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return "", err
	}
	return c.getClient().Get(ctx, key)
}

func (c *poolRefreshingClient) GetDel(ctx context.Context, key string) (string, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return "", err
	}
	return c.getClient().GetDel(ctx, key)
}

func (c *poolRefreshingClient) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.monitorStop != nil {
		c.monitorStop()
	}
	return c.getClient().Close()
}

func (c *poolRefreshingClient) PingResult(ctx context.Context) (string, error) {
	return c.getClient().PingResult(ctx)
}

func (c *poolRefreshingClient) ConfigurationSubscribe(ctx context.Context, args *ConfigurationSubscribeArgs) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return
	}
	c.getClient().ConfigurationSubscribe(ctx, args)
}

func (c *poolRefreshingClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (*bool, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err
	}
	return c.getClient().SetNX(ctx, key, value, expiration)
}

func (c *poolRefreshingClient) EvalInt(ctx context.Context, script string, keys []string, args ...interface{}) (*int, error, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err, err
	}
	return c.getClient().EvalInt(ctx, script, keys, args...)
}

func (c *poolRefreshingClient) XAdd(ctx context.Context, stream string, maxLenApprox int64, streamTTL string, values map[string]interface{}) (string, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return "", err
	}
	return c.getClient().XAdd(ctx, stream, maxLenApprox, streamTTL, values)
}

func (c *poolRefreshingClient) XGroupCreateMkStream(ctx context.Context, stream string, group string, start string) error {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return err
	}
	return c.getClient().XGroupCreateMkStream(ctx, stream, group, start)
}

func (c *poolRefreshingClient) XAck(ctx context.Context, stream string, group string, messageID string) error {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return err
	}
	return c.getClient().XAck(ctx, stream, group, messageID)
}

func (c *poolRefreshingClient) XReadGroupResult(ctx context.Context, group string, consumer string, streams []string, count int64, block time.Duration) ([]RedisXStream, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err
	}
	return c.getClient().XReadGroupResult(ctx, group, consumer, streams, count, block)
}

func (c *poolRefreshingClient) XPendingExtResult(ctx context.Context, stream string, group string, start string, end string, count int64) ([]RedisXPendingExt, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err
	}
	return c.getClient().XPendingExtResult(ctx, stream, group, start, end, count)
}

func (c *poolRefreshingClient) XClaimResult(ctx context.Context, stream string, group string, consumer string, minIdleTime time.Duration, messageIDs []string) ([]RedisXMessage, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return nil, err
	}
	return c.getClient().XClaimResult(ctx, stream, group, consumer, minIdleTime, messageIDs)
}

func (c *poolRefreshingClient) TxPipeline() RedisPipeliner {
	_ = c.ensureLiveConnection(context.Background())
	return c.getClient().TxPipeline()
}

func (c *poolRefreshingClient) TTLResult(ctx context.Context, key string) (time.Duration, error) {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return 0, err
	}
	return c.getClient().TTLResult(ctx, key)
}

func (c *poolRefreshingClient) AuthACL(ctx context.Context, username, password string) error {
	if err := c.ensureLiveConnection(ctx); err != nil {
		return err
	}
	return c.getClient().AuthACL(ctx, username, password)
}
