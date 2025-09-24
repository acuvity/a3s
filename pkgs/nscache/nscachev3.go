package nscache

import (
	"context"
	"log/slog"
	"time"

	ccache3 "github.com/karlseguin/ccache/v3"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
)

// A NamespacedCache is used to cache namespaced information.
// The cache will invalidate all items when their namespace is
// deleted or updated.
type NamespacedCacheV3[T any] struct {
	pubsub           bahamut.PubSubClient
	cache            *ccache3.Cache[T]
	notificationName string
}

// New returns a new namespace cache.
func NewV3[T any](pubsub bahamut.PubSubClient, maxSize int64, options ...Option) *NamespacedCacheV3[T] {

	cfg := newConfig()
	for _, o := range options {
		o(&cfg)
	}

	return &NamespacedCacheV3[T]{
		pubsub:           pubsub,
		cache:            ccache3.New(ccache3.Configure[T]().MaxSize(maxSize)),
		notificationName: cfg.notificationName,
	}
}

// Set sets a new namespaced key with the given value, with given expiration.
// namespace must be set. key is optional. It can be empty if you wish to only associate
// one value to one namespace.
func (c *NamespacedCacheV3[T]) Set(namespace string, key string, value T, duration time.Duration) {

	c.cache.Set(namespace+":"+key, value, duration)
}

// Get returns the cached item for the provided namespaced key.
func (c *NamespacedCacheV3[T]) Get(namespace string, key string) *ccache3.Item[T] {

	return c.cache.Get(namespace + ":" + key)
}

// Delete attempts to delete an item from the cache using the given namespace and key.
func (c *NamespacedCacheV3[T]) Delete(namespace string, key string) bool {

	return c.cache.Delete(namespace + ":" + key)
}

// Start starts listening to notifications for automatic invalidation
func (c *NamespacedCacheV3[T]) Start(ctx context.Context) {

	notification.Subscribe(
		ctx,
		c.pubsub,
		c.notificationName,
		func(msg *notification.Message) {
			if msg.Data != nil {
				c.cleanupCacheForNamespace(msg.Data.(string))
			} else {
				slog.Error("Received namespace change notification without data", "msg", msg.Type, "data", msg.Data)
			}
		},
	)
}

func (c *NamespacedCacheV3[T]) cleanupCacheForNamespace(ns string) {

	suffix := "/"
	if ns == "/" {
		suffix = ""
	}

	c.cache.DeletePrefix(ns + ":")
	c.cache.DeletePrefix(ns + suffix)
}
