package main

import (
	"context"
	"fmt"
	"time"

	"github.com/dapr/components-contrib/metadata"
	"github.com/dapr/components-contrib/pubsub"
	redispubsub "github.com/dapr/components-contrib/pubsub/redis"
	"github.com/dapr/kit/logger"
)

func main() {
	l := logger.NewLogger("redis-sentinel-test")
	l.SetOutputLevel(logger.DebugLevel)

	p := redispubsub.NewRedisStreams(l)

	props := map[string]string{
		"redisHost":          "redis-sentinel:26379",
		"redisPassword":      "password123",
		"failover":           "true",
		"sentinelMasterName": "mymaster",
		"redisMaxRetries":    "0",
		"writeTimeout":       "1s",
		"readTimeout":        "1s",
	}

	req := pubsub.Metadata{
		Base: metadata.Base{Properties: props},
	}

	ctx := context.Background()

	err := p.Init(ctx, req)
	if err != nil {
		l.Fatalf("Init failed: %v", err)
	}

	req1 := &pubsub.PublishRequest{Data: []byte("first"), PubsubName: "test-pubsub", Topic: "test-topic"}
	if err := p.Publish(ctx, req1); err != nil {
		fmt.Printf("First publish failed: %v\n", err)
	} else {
		fmt.Println("First publish succeeded")
	}

	time.Sleep(15 * time.Second)

	req2 := &pubsub.PublishRequest{Data: []byte("second"), PubsubName: "test-pubsub", Topic: "test-topic"}
	if err := p.Publish(ctx, req2); err != nil {
		fmt.Printf("\n--- REPRODUCED ERROR ---\nSecond publish failed: %v\n------------------------\n", err)
	} else {
		fmt.Println("Second publish succeeded")
	}
}
