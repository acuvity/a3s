package samlceremony

import (
	"context"
	"errors"
	"time"

	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	bson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const collection = "samlcache"

var (
	getDatabase     = manipmongo.GetDatabase
	insertCacheItem = func(ctx context.Context, db *mongo.Database, item *CacheItem) error {
		_, err := db.Collection(collection).InsertOne(ctx, item)
		return err
	}
	findCacheItem = func(ctx context.Context, db *mongo.Database, state string, item *CacheItem) error {
		return db.Collection(collection).FindOne(ctx, bson.M{"state": state}).Decode(item)
	}
	deleteCacheItem = func(ctx context.Context, db *mongo.Database, state string) error {
		_, err := db.Collection(collection).DeleteOne(ctx, bson.M{"state": state})
		return err
	}
)

// CacheItem represents a cache OIDC request info.
type CacheItem struct {
	State              string    `bson:"state"`
	ACSURL             string    `bson:"acsurl"`
	AuthorizeRequestID string    `bson:"authorizerequestid,omitempty"`
	Time               time.Time `bson:"time"`
}

// Set sets the given OIDCRequestItem in redis.
func Set(m manipulate.Manipulator, item *CacheItem) error {

	item.Time = time.Now()

	db, err := getDatabase(m)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return insertCacheItem(ctx, db, item)
}

// Get gets the items with the given state.
// If none is found, it will return nil.
func Get(m manipulate.Manipulator, state string) (*CacheItem, error) {

	db, err := getDatabase(m)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	item := &CacheItem{}
	if err := findCacheItem(ctx, db, state, item); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return item, nil
}

// Delete deletes the items with the given state.
func Delete(m manipulate.Manipulator, state string) error {

	db, err := getDatabase(m)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return deleteCacheItem(ctx, db, state)
}
