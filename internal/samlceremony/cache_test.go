package samlceremony

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
	"go.mongodb.org/mongo-driver/v2/mongo"
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

func resetCacheSeams(t *testing.T) {
	t.Helper()

	oldGetDatabase := getDatabase
	oldInsertCacheItem := insertCacheItem
	oldFindCacheItem := findCacheItem
	oldDeleteCacheItem := deleteCacheItem
	t.Cleanup(func() {
		getDatabase = oldGetDatabase
		insertCacheItem = oldInsertCacheItem
		findCacheItem = oldFindCacheItem
		deleteCacheItem = oldDeleteCacheItem
	})
}

func TestSetGetDeleteUseMongoCacheOperations(t *testing.T) {
	resetCacheSeams(t)

	getDatabase = func(manipulate.Manipulator) (*mongo.Database, error) {
		return nil, nil
	}

	item := &CacheItem{
		State:  "state-1",
		ACSURL: "https://acs.example.com",
	}
	before := time.Now()

	insertCacheItem = func(ctx context.Context, db *mongo.Database, inserted *CacheItem) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatalf("expected Set context deadline")
		}
		if db != nil {
			t.Fatalf("expected stub database to be nil")
		}
		if inserted != item {
			t.Fatalf("expected Set to pass the original item")
		}
		return nil
	}
	if err := Set(nil, item); err != nil {
		t.Fatalf("Set returned unexpected error: %v", err)
	}
	if item.Time.Before(before) {
		t.Fatalf("expected Set to stamp the cache item time")
	}

	findCacheItem = func(ctx context.Context, db *mongo.Database, state string, found *CacheItem) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatalf("expected Get context deadline")
		}
		if state != item.State {
			t.Fatalf("unexpected lookup state %q", state)
		}
		found.State = state
		found.ACSURL = item.ACSURL
		return nil
	}
	got, err := Get(nil, item.State)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if got == nil || got.State != item.State || got.ACSURL != item.ACSURL {
		t.Fatalf("unexpected cache item: %#v", got)
	}

	deleteCacheItem = func(ctx context.Context, db *mongo.Database, state string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatalf("expected Delete context deadline")
		}
		if state != item.State {
			t.Fatalf("unexpected delete state %q", state)
		}
		return nil
	}
	if err := Delete(nil, item.State); err != nil {
		t.Fatalf("Delete returned unexpected error: %v", err)
	}
}

func TestGetReturnsNilWhenCacheItemIsMissing(t *testing.T) {
	resetCacheSeams(t)

	getDatabase = func(manipulate.Manipulator) (*mongo.Database, error) { return nil, nil }
	findCacheItem = func(context.Context, *mongo.Database, string, *CacheItem) error {
		return mongo.ErrNoDocuments
	}

	got, err := Get(nil, "missing")
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected missing cache item to return nil, got %#v", got)
	}
}

func TestCacheOperationErrorsAreReturned(t *testing.T) {
	resetCacheSeams(t)

	sentinel := errors.New("cache operation failed")
	getDatabase = func(manipulate.Manipulator) (*mongo.Database, error) { return nil, nil }

	insertCacheItem = func(context.Context, *mongo.Database, *CacheItem) error { return sentinel }
	if err := Set(nil, &CacheItem{}); !errors.Is(err, sentinel) {
		t.Fatalf("expected Set error %v, got %v", sentinel, err)
	}

	findCacheItem = func(context.Context, *mongo.Database, string, *CacheItem) error { return sentinel }
	if _, err := Get(nil, "state-1"); !errors.Is(err, sentinel) {
		t.Fatalf("expected Get error %v, got %v", sentinel, err)
	}

	deleteCacheItem = func(context.Context, *mongo.Database, string) error { return sentinel }
	if err := Delete(nil, "state-1"); !errors.Is(err, sentinel) {
		t.Fatalf("expected Delete error %v, got %v", sentinel, err)
	}
}

func TestCacheDatabaseErrorsAreReturned(t *testing.T) {
	resetCacheSeams(t)

	sentinel := errors.New("database unavailable")
	getDatabase = func(manipulate.Manipulator) (*mongo.Database, error) { return nil, sentinel }

	if err := Set(nil, &CacheItem{}); !errors.Is(err, sentinel) {
		t.Fatalf("expected Set database error %v, got %v", sentinel, err)
	}
	if _, err := Get(nil, "state-1"); !errors.Is(err, sentinel) {
		t.Fatalf("expected Get database error %v, got %v", sentinel, err)
	}
	if err := Delete(nil, "state-1"); !errors.Is(err, sentinel) {
		t.Fatalf("expected Delete database error %v, got %v", sentinel, err)
	}
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
