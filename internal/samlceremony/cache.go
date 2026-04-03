package samlceremony

import (
	"context"
	"time"

	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	bson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const collection = "samlcache"

// CacheItem represents a cache OIDC request info.
type CacheItem struct {
	State  string    `bson:"state"`
	ACSURL string    `bson:"acsurl"`
	Time   time.Time `bson:"time"`
}

// Set sets the given OIDCRequestItem in redis.
func Set(m manipulate.Manipulator, item *CacheItem) error {

	item.Time = time.Now()

	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = db.Collection(collection).InsertOne(ctx, item)
	return err
}

// Get gets the items with the given state.
// If none is found, it will return nil.
func Get(m manipulate.Manipulator, state string) (*CacheItem, error) {

	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	item := &CacheItem{}
	if err := db.Collection(collection).FindOne(ctx, bson.M{"state": state}).Decode(item); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return item, nil
}

// Delete deletes the items with the given state.
func Delete(m manipulate.Manipulator, state string) error {

	db, err := manipmongo.GetDatabase(m)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = db.Collection(collection).DeleteOne(ctx, bson.M{"state": state})
	return err
}
