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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type refreshTestClient struct {
	pingErr    atomic.Value
	pingCnt    atomic.Int32
	doWriteCnt atomic.Int32
	closeCount atomic.Int32
}

func (c *refreshTestClient) IsNilValueError(error) bool { return false }
func (c *refreshTestClient) Context() context.Context   { return context.Background() }
func (c *refreshTestClient) DoRead(context.Context, ...interface{}) (interface{}, error) {
	return nil, nil
}
func (c *refreshTestClient) DoWrite(context.Context, ...interface{}) error {
	c.doWriteCnt.Add(1)
	return nil
}
func (c *refreshTestClient) Del(context.Context, ...string) error           { return nil }
func (c *refreshTestClient) Get(context.Context, string) (string, error)    { return "", nil }
func (c *refreshTestClient) GetDel(context.Context, string) (string, error) { return "", nil }
func (c *refreshTestClient) Close() error {
	c.closeCount.Add(1)
	return nil
}
func (c *refreshTestClient) PingResult(context.Context) (string, error) {
	c.pingCnt.Add(1)
	if v := c.pingErr.Load(); v != nil {
		if err, ok := v.(error); ok {
			return "", err
		}
	}
	return "", nil
}
func (c *refreshTestClient) ConfigurationSubscribe(context.Context, *ConfigurationSubscribeArgs) {}
func (c *refreshTestClient) SetNX(context.Context, string, interface{}, time.Duration) (*bool, error) {
	v := true
	return &v, nil
}
func (c *refreshTestClient) EvalInt(context.Context, string, []string, ...interface{}) (*int, error, error) {
	v := 0
	return &v, nil, nil
}
func (c *refreshTestClient) XAdd(context.Context, string, int64, string, map[string]interface{}) (string, error) {
	return "", nil
}
func (c *refreshTestClient) XGroupCreateMkStream(context.Context, string, string, string) error {
	return nil
}
func (c *refreshTestClient) XAck(context.Context, string, string, string) error { return nil }
func (c *refreshTestClient) XReadGroupResult(context.Context, string, string, []string, int64, time.Duration) ([]RedisXStream, error) {
	return nil, nil
}
func (c *refreshTestClient) XPendingExtResult(context.Context, string, string, string, string, int64) ([]RedisXPendingExt, error) {
	return nil, nil
}
func (c *refreshTestClient) XClaimResult(context.Context, string, string, string, time.Duration, []string) ([]RedisXMessage, error) {
	return nil, nil
}
func (c *refreshTestClient) TxPipeline() RedisPipeliner                               { return nil }
func (c *refreshTestClient) TTLResult(context.Context, string) (time.Duration, error) { return 0, nil }
func (c *refreshTestClient) AuthACL(context.Context, string, string) error            { return nil }

func TestPoolRefreshingClientRefreshesOnExplicitTrigger(t *testing.T) {
	oldClient := &refreshTestClient{}
	newClient := &refreshTestClient{}

	refreshCalls := 0
	client := newPoolRefreshingClient(oldClient, func() (RedisClient, error) {
		refreshCalls++
		return newClient, nil
	}, nil, false, 0).(*poolRefreshingClient)

	client.refreshPool("test sentinel switch")
	assert.Equal(t, 1, refreshCalls)
	assert.EqualValues(t, 1, oldClient.closeCount.Load())

	err := client.DoWrite(t.Context(), "SET", "a", "2")
	require.NoError(t, err)
}

func TestPoolRefreshingClientStopsMonitorOnClose(t *testing.T) {
	baseClient := &refreshTestClient{}

	client := newPoolRefreshingClient(baseClient, func() (RedisClient, error) {
		return &refreshTestClient{}, nil
	}, nil, false, 0).(*poolRefreshingClient)

	client.monitorStop = func() {}
	require.NoError(t, client.Close())
	assert.EqualValues(t, 1, baseClient.closeCount.Load())
}

func TestPoolRefreshingClientPeriodicRefresh(t *testing.T) {
	oldClient := &refreshTestClient{}

	refreshCalls := atomic.Int32{}
	client := newPoolRefreshingClient(oldClient, func() (RedisClient, error) {
		refreshCalls.Add(1)
		return &refreshTestClient{}, nil
	}, nil, false, 0).(*poolRefreshingClient)

	client.startMonitors(false, &Settings{PoolRefreshInterval: Duration(10 * time.Millisecond)})
	defer client.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for (refreshCalls.Load() == 0 || oldClient.closeCount.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	assert.GreaterOrEqual(t, refreshCalls.Load(), int32(1))
	assert.GreaterOrEqual(t, oldClient.closeCount.Load(), int32(1))
}

func TestPoolRefreshingClientValidateBeforeUse(t *testing.T) {
	oldClient := &refreshTestClient{}
	oldClient.pingErr.Store(assert.AnError)
	newClient := &refreshTestClient{}

	refreshCalls := atomic.Int32{}
	client := newPoolRefreshingClient(oldClient, func() (RedisClient, error) {
		refreshCalls.Add(1)
		return newClient, nil
	}, nil, true, 0).(*poolRefreshingClient)

	err := client.DoWrite(t.Context(), "SET", "a", "1")
	require.NoError(t, err)
	assert.EqualValues(t, 1, refreshCalls.Load())
	assert.EqualValues(t, 1, oldClient.closeCount.Load())
	assert.EqualValues(t, 1, newClient.doWriteCnt.Load())
}

func TestPoolRefreshingClientValidateBeforeUseHonorsInterval(t *testing.T) {
	baseClient := &refreshTestClient{}

	client := newPoolRefreshingClient(baseClient, func() (RedisClient, error) {
		return &refreshTestClient{}, nil
	}, nil, true, time.Hour).(*poolRefreshingClient)

	require.NoError(t, client.DoWrite(t.Context(), "SET", "a", "1"))
	require.NoError(t, client.DoWrite(t.Context(), "SET", "a", "2"))

	assert.EqualValues(t, 1, baseClient.pingCnt.Load())
	assert.EqualValues(t, 2, baseClient.doWriteCnt.Load())
}
