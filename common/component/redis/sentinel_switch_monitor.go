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
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	v8 "github.com/go-redis/redis/v8"
	v9 "github.com/redis/go-redis/v9"

	kitlogger "github.com/dapr/kit/logger"
)

const sentinelSwitchMasterChannel = "+switch-master"

func runSentinelSwitchMonitorV8(ctx context.Context, s *Settings, logger *kitlogger.Logger, onSwitch func(reason string)) {
	runSentinelSwitchMonitor(ctx, s, logger, onSwitch, func(addr string, tlsConfig *tls.Config) sentinelSubscriber {
		return &sentinelSubscriberV8{client: v8.NewSentinelClient(&v8.Options{
			Addr:         addr,
			Username:     s.SentinelUsername,
			Password:     s.SentinelPassword,
			DialTimeout:  sentinelDialTimeout(s),
			ReadTimeout:  sentinelReadTimeout(s),
			WriteTimeout: sentinelWriteTimeout(s),
			TLSConfig:    tlsConfig,
		})}
	})
}

func runSentinelSwitchMonitorV9(ctx context.Context, s *Settings, logger *kitlogger.Logger, onSwitch func(reason string)) {
	runSentinelSwitchMonitor(ctx, s, logger, onSwitch, func(addr string, tlsConfig *tls.Config) sentinelSubscriber {
		return &sentinelSubscriberV9{client: v9.NewSentinelClient(&v9.Options{
			Addr:         addr,
			Username:     s.SentinelUsername,
			Password:     s.SentinelPassword,
			DialTimeout:  sentinelDialTimeout(s),
			ReadTimeout:  sentinelReadTimeout(s),
			WriteTimeout: sentinelWriteTimeout(s),
			TLSConfig:    tlsConfig,
		})}
	})
}

type sentinelSubscriber interface {
	subscribe(ctx context.Context) (<-chan string, error)
	close() error
}

type sentinelSubscriberV8 struct {
	client *v8.SentinelClient
	pubsub *v8.PubSub
}

func (s *sentinelSubscriberV8) subscribe(ctx context.Context) (<-chan string, error) {
	s.pubsub = s.client.Subscribe(ctx, sentinelSwitchMasterChannel)
	if _, err := s.pubsub.Receive(ctx); err != nil {
		return nil, err
	}

	out := make(chan string)
	go func() {
		defer close(out)
		for msg := range s.pubsub.Channel() {
			out <- msg.Payload
		}
	}()
	return out, nil
}

func (s *sentinelSubscriberV8) close() error {
	if s.pubsub != nil {
		_ = s.pubsub.Close()
	}
	return s.client.Close()
}

type sentinelSubscriberV9 struct {
	client *v9.SentinelClient
	pubsub *v9.PubSub
}

func (s *sentinelSubscriberV9) subscribe(ctx context.Context) (<-chan string, error) {
	s.pubsub = s.client.Subscribe(ctx, sentinelSwitchMasterChannel)
	if _, err := s.pubsub.Receive(ctx); err != nil {
		return nil, err
	}

	out := make(chan string)
	go func() {
		defer close(out)
		for msg := range s.pubsub.Channel() {
			out <- msg.Payload
		}
	}()
	return out, nil
}

func (s *sentinelSubscriberV9) close() error {
	if s.pubsub != nil {
		_ = s.pubsub.Close()
	}
	return s.client.Close()
}

func runSentinelSwitchMonitor(
	ctx context.Context,
	s *Settings,
	logger *kitlogger.Logger,
	onSwitch func(reason string),
	newSubscriber func(addr string, tlsConfig *tls.Config) sentinelSubscriber,
) {
	addrs := sentinelAddrs(s)
	if len(addrs) == 0 {
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}

		tlsConfig, err := sentinelTLSConfig(s)
		if err != nil {
			if logger != nil {
				(*logger).Warnf("redis client: sentinel monitor TLS configuration failed: %v", err)
			}
			return
		}

		connected := false
		for _, addr := range addrs {
			sub := newSubscriber(addr, tlsConfig)
			ch, subErr := sub.subscribe(ctx)
			if subErr != nil {
				_ = sub.close()
				continue
			}
			connected = true
			if logger != nil {
				(*logger).Infof("redis client: listening for Sentinel %s on %s", sentinelSwitchMasterChannel, addr)
			}

			for {
				select {
				case <-ctx.Done():
					_ = sub.close()
					return
				case payload, ok := <-ch:
					if !ok {
						_ = sub.close()
						goto nextAddr
					}
					if !sentinelSwitchMatchesMaster(payload, s.SentinelMasterName) {
						continue
					}
					onSwitch(fmt.Sprintf("sentinel %s %s", sentinelSwitchMasterChannel, payload))
				}
			}
		nextAddr:
		}

		if !connected && logger != nil {
			(*logger).Warn("redis client: unable to subscribe to Sentinel switch events; retrying")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func sentinelAddrs(s *Settings) []string {
	parts := strings.Split(s.Host, ",")
	addrs := make([]string, 0, len(parts))
	for _, p := range parts {
		addr := strings.TrimSpace(p)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func sentinelSwitchMatchesMaster(payload string, master string) bool {
	if master == "" {
		return true
	}
	fields := strings.Fields(payload)
	if len(fields) == 0 {
		return false
	}
	return fields[0] == master
}

func sentinelDialTimeout(s *Settings) time.Duration {
	if s.DialTimeout > 0 {
		return time.Duration(s.DialTimeout)
	}
	return 5 * time.Second
}

func sentinelReadTimeout(s *Settings) time.Duration {
	if s.ReadTimeout > 0 {
		return time.Duration(s.ReadTimeout)
	}
	return 5 * time.Second
}

func sentinelWriteTimeout(s *Settings) time.Duration {
	if s.WriteTimeout > 0 {
		return time.Duration(s.WriteTimeout)
	}
	return 5 * time.Second
}

func sentinelTLSConfig(s *Settings) (*tls.Config, error) {
	if !s.EnableTLS {
		return nil, nil
	}

	cfg := &tls.Config{
		InsecureSkipVerify: s.InsecureSkipTLSVerify, //nolint:gosec
	}
	err := s.SetCertificate(func(cert *tls.Certificate) {
		cfg.Certificates = []tls.Certificate{*cert}
	})
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
