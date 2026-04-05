package oauth2ceremony

import (
	"testing"
	"time"

	"go.acuvity.ai/manipulate/maniptest"
	"golang.org/x/oauth2"
)

func assertPanicWithMessage(t *testing.T, expected string, fn func()) {
	t.Helper()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic %q", expected)
		}
		if r != expected {
			t.Fatalf("expected panic %q, got %v", expected, r)
		}
	}()

	fn()
}

func TestSetGetDeleteRequireMongoManipulator(t *testing.T) {
	m := maniptest.NewTestManipulator()
	item := &CacheItem{
		State:        "state-1",
		OAuth2Config: oauth2.Config{ClientID: "client"},
	}

	before := time.Now()
	assertPanicWithMessage(t, "you can only pass a mongo manipulator to GetDatabase", func() {
		_ = Set(m, item)
	})
	if item.Time.Before(before) {
		t.Fatalf("expected Set to stamp the cache item time before panicking")
	}

	assertPanicWithMessage(t, "you can only pass a mongo manipulator to GetDatabase", func() {
		_, _ = Get(m, item.State)
	})

	assertPanicWithMessage(t, "you can only pass a mongo manipulator to GetDatabase", func() {
		_ = Delete(m, item.State)
	})
}
