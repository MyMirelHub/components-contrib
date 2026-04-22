package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type subscription struct {
	PubsubName string            `json:"pubsubname"`
	Topic      string            `json:"topic"`
	Route      string            `json:"route"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

var inFlight atomic.Int32
var blockedUntil atomic.Int64

type busyStrategy string

const (
	busyImmediate429 busyStrategy = "immediate429"
	busyInternalRetry busyStrategy = "internalRetry"
)

type appConfig struct {
	maxConcurrency    int32
	strategy          busyStrategy
	workDuration      time.Duration
	internalRetries   int
	internalRetryWait time.Duration
	sleepAfterExhaust bool
	sleepDuration     time.Duration
}

func getMaxConcurrency() int32 {
	v := os.Getenv("APP_MAX_CONCURRENCY")
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Printf("invalid APP_MAX_CONCURRENCY=%q, defaulting to 1", v)
		return 1
	}
	return int32(n)
}

func parseDurationEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("invalid %s=%q, defaulting to %s", key, v, def)
		return def
	}
	return d
}

func parseIntEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Printf("invalid %s=%q, defaulting to %d", key, v, def)
		return def
	}
	return n
}

func parseBoolEnv(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Printf("invalid %s=%q, defaulting to %t", key, v, def)
		return def
	}
	return b
}

func getBusyStrategy() busyStrategy {
	v := strings.TrimSpace(os.Getenv("APP_BUSY_STRATEGY"))
	v = strings.ToLower(v)
	switch v {
	case "", strings.ToLower(string(busyImmediate429)):
		return busyImmediate429
	case strings.ToLower(string(busyInternalRetry)):
		return busyInternalRetry
	default:
		log.Printf("invalid APP_BUSY_STRATEGY=%q, defaulting to %s", v, busyImmediate429)
		return busyImmediate429
	}
}

func loadConfig() appConfig {
	return appConfig{
		maxConcurrency:    getMaxConcurrency(),
		strategy:          getBusyStrategy(),
		workDuration:      parseDurationEnv("APP_WORK_DURATION", 2*time.Second),
		internalRetries:   parseIntEnv("APP_INTERNAL_MAX_RETRIES", 20),
		internalRetryWait: parseDurationEnv("APP_INTERNAL_RETRY_DELAY", 200*time.Millisecond),
		sleepAfterExhaust: parseBoolEnv("APP_SLEEP_AFTER_EXHAUST", false),
		sleepDuration:     parseDurationEnv("APP_SLEEP_DURATION", 30*time.Second),
	}
}

func (c appConfig) String() string {
	return fmt.Sprintf("maxConcurrency=%d strategy=%s workDuration=%s internalRetries=%d internalRetryWait=%s sleepAfterExhaust=%t sleepDuration=%s",
		c.maxConcurrency,
		c.strategy,
		c.workDuration,
		c.internalRetries,
		c.internalRetryWait,
		c.sleepAfterExhaust,
		c.sleepDuration,
	)
}

func tryAcquire(maxConcurrency int32) bool {
	current := inFlight.Add(1)
	if current > maxConcurrency {
		inFlight.Add(-1)
		return false
	}
	return true
}

func rejectBusy(w http.ResponseWriter) {
	log.Printf("app busy: returning 429 to trigger RETRY")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("busy"))
}

func maybeBlockedBySleepMode() bool {
	until := blockedUntil.Load()
	if until <= 0 {
		return false
	}
	if time.Now().UnixNano() < until {
		return true
	}
	blockedUntil.CompareAndSwap(until, 0)
	return false
}

func main() {
	cfg := loadConfig()
	log.Printf("configured %s", cfg.String())

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Dapr discovers subscriptions through this endpoint.
	mux.HandleFunc("/dapr/subscribe", func(w http.ResponseWriter, r *http.Request) {
		subs := []subscription{
			{
				PubsubName: "messagebus",
				Topic:      "storm-topic",
				Route:      "/orders",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(subs)
	})

	// Intentionally emulate app-level capacity control:
	// if in-flight messages reach app max concurrency, either return 429 immediately
	// or internally retry acquisition to emulate app-side retry loops.
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		if maybeBlockedBySleepMode() {
			rejectBusy(w)
			return
		}

		acquired := tryAcquire(cfg.maxConcurrency)
		if !acquired {
			switch cfg.strategy {
			case busyImmediate429:
				rejectBusy(w)
				return
			case busyInternalRetry:
				for attempt := 1; attempt <= cfg.internalRetries; attempt++ {
					time.Sleep(cfg.internalRetryWait)
					if maybeBlockedBySleepMode() {
						rejectBusy(w)
						return
					}
					if tryAcquire(cfg.maxConcurrency) {
						log.Printf("internal retry acquired capacity after %d attempts", attempt)
						acquired = true
						break
					}
				}
				if !acquired {
					if cfg.sleepAfterExhaust {
						until := time.Now().Add(cfg.sleepDuration).UnixNano()
						blockedUntil.Store(until)
						log.Printf("internal retries exhausted (%d), entering sleep mode for %s", cfg.internalRetries, cfg.sleepDuration)
					} else {
						log.Printf("internal retries exhausted (%d), returning 429", cfg.internalRetries)
					}
					rejectBusy(w)
					return
				}
			}
		}

		defer inFlight.Add(-1)
		time.Sleep(cfg.workDuration)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":8080"
	log.Printf("starting app on %s (pid=%d)", addr, os.Getpid())
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
