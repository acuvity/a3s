package samlceremony

import (
	"testing"
	"time"

	"go.acuvity.ai/manipulate/maniptest"
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
		State:  "state-1",
		ACSURL: "https://acs.example.com",
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
