package oauth2ceremony

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
	"golang.org/x/oauth2"
)

const collection = "oauth2cache"

// CacheItem represents a cache OIDC request info.
type CacheItem struct {
	State        string        `bson:"state"`
	OAuth2Config oauth2.Config `bson:"oauth2config"`
	Time         time.Time     `bson:"time"`
}

// Set sets the given OIDCRequestItem in redis.
func Set(m manipulate.Manipulator, item *CacheItem) error {

	item.Time = time.Now()

	db, disco, err := manipmongo.GetDatabase(m)
	if err != nil {
		return err
	}
	defer disco()

	return db.C(collection).Insert(item)
}

// Get gets the items with the given state.
// If none is found, it will return nil.
func Get(m manipulate.Manipulator, state string) (*CacheItem, error) {

	db, disco, err := manipmongo.GetDatabase(m)
	if err != nil {
		return nil, err
	}
	defer disco()

	item := &CacheItem{}
	if err := db.C(collection).Find(bson.M{"state": state}).One(item); err != nil {
		return nil, err
	}
	return item, nil
}

// Delete deletes the items with the given state.
func Delete(m manipulate.Manipulator, state string) error {

	db, disco, err := manipmongo.GetDatabase(m)
	if err != nil {
		return err
	}
	defer disco()

	return db.C(collection).Remove(bson.M{"state": state})
}
