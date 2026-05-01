package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
)

const (
	authorizeContextsCollection = "oauthauthorizecontexts"
	sessionsCollection          = "oauthsessions"
)

// store is the Mongo-backed persistence layer for OAuth clients, contexts, and
// sessions.
type store struct {
	manipulator manipulate.Manipulator
}

// newStore returns a new OAuth store.
func newStore(manipulator manipulate.Manipulator) *store {
	return &store{manipulator: manipulator}
}

// EnsureIndexes creates the indexes needed by the OAuth store collections.
func EnsureIndexes(manipulator manipulate.Manipulator) error {
	// TTL cleanup for short-lived authorization-code sessions.
	if err := manipmongo.EnsureIndex(manipulator, collectionIdentity(sessionsCollection), mgo.Index{
		Key:         []string{"expiresat"},
		ExpireAfter: time.Minute,
		Name:        "index_expiration_expiresat",
		Background:  true,
	}); err != nil {
		return fmt.Errorf("ensure oauth session expiration index: %w", err)
	}

	// Unique lookup key for exchanging authorization codes exactly once.
	if err := manipmongo.EnsureIndex(manipulator, collectionIdentity(sessionsCollection), mgo.Index{
		Key:        []string{"code"},
		Unique:     true,
		Name:       "index_code",
		Background: true,
	}); err != nil {
		return fmt.Errorf("ensure oauth session code index: %w", err)
	}

	// TTL cleanup for short-lived pending authorize contexts.
	if err := manipmongo.EnsureIndex(manipulator, collectionIdentity(authorizeContextsCollection), mgo.Index{
		Key:         []string{"expiresat"},
		ExpireAfter: time.Minute,
		Name:        "index_expiration_expiresat",
		Background:  true,
	}); err != nil {
		return fmt.Errorf("ensure oauth authorize context expiration index: %w", err)
	}

	// Unique lookup key for resuming the browser flow by authorize request ID.
	if err := manipmongo.EnsureIndex(manipulator, collectionIdentity(authorizeContextsCollection), mgo.Index{
		Key:        []string{"id"},
		Unique:     true,
		Name:       "index_id",
		Background: true,
	}); err != nil {
		return fmt.Errorf("ensure oauth authorize context id index: %w", err)
	}

	return nil
}

// getClient resolves the per-namespace client registration.
func (s *store) getClient(ctx context.Context, namespace string, clientID string) (*api.OAuthClient, error) {
	clients := &api.OAuthClientsList{}
	mctx := manipulate.NewContext(
		ctx,
		manipulate.ContextOptionNamespace(namespace),
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().
				WithKey("clientid").Equals(clientID).
				Done(),
		),
	)

	if err := s.manipulator.RetrieveMany(mctx, clients); err != nil {
		return nil, err
	}

	switch len(*clients) {
	case 0:
		return nil, mgo.ErrNotFound
	case 1:
		return (*clients)[0], nil
	default:
		return nil, fmt.Errorf("more than one oauth client found")
	}
}

// getOAuthApplication resolves an oauth application by namespace and id.
func (s *store) getOAuthApplication(ctx context.Context, namespace string, id string) (*api.OAuthApplication, error) {
	obj := api.NewOAuthApplication()
	obj.SetIdentifier(id)

	if err := s.manipulator.Retrieve(
		manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(namespace)),
		obj,
	); err != nil {
		return nil, err
	}
	if obj.Namespace != namespace {
		return nil, fmt.Errorf("oauth application namespace mismatch")
	}

	return obj, nil
}

// loadAuthorizeContext resolves an authorize request together with its client
// registration and oauth application.
func (s *store) loadAuthorizeContext(ctx context.Context, authorizeRequestID string) (*AuthorizeContext, *api.OAuthClient, *api.OAuthApplication, error) {
	authorizeContext, err := s.getAuthorizeContext(authorizeRequestID)
	if err != nil {
		return nil, nil, nil, err
	}
	if authorizeContext.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, nil, ErrAuthorizeContextExpired
	}

	client, err := s.getClient(ctx, authorizeContext.Namespace, authorizeContext.ClientID)
	if err != nil {
		return nil, nil, nil, err
	}
	if client.OauthApplicationID != authorizeContext.OAuthApplicationID ||
		client.OauthApplicationNamespace != authorizeContext.OAuthApplicationNamespace {
		return nil, nil, nil, ErrAuthorizeContextMismatch
	}

	app, err := s.getOAuthApplication(ctx, authorizeContext.OAuthApplicationNamespace, authorizeContext.OAuthApplicationID)
	if err != nil {
		return nil, nil, nil, err
	}
	if !app.Enabled {
		return nil, nil, nil, ErrOAuthApplicationDisabled
	}

	return authorizeContext, client, app, nil
}

// createAuthorizeContext stores the immutable authorize context.
func (s *store) createAuthorizeContext(context *AuthorizeContext) error {
	db, disco, err := manipmongo.GetDatabase(s.manipulator)
	if err != nil {
		return err
	}
	defer disco()

	return db.C(authorizeContextsCollection).Insert(context)
}

// getAuthorizeContext loads the immutable authorize context.
func (s *store) getAuthorizeContext(id string) (*AuthorizeContext, error) {
	db, disco, err := manipmongo.GetDatabase(s.manipulator)
	if err != nil {
		return nil, err
	}
	defer disco()

	rec := &AuthorizeContext{}
	if err := db.C(authorizeContextsCollection).Find(bson.M{"id": id}).One(rec); err != nil {
		return nil, err
	}

	return rec, nil
}

// createOAuthSession stores the unified OAuth session payload.
func (s *store) createOAuthSession(session *Session) error {
	db, disco, err := manipmongo.GetDatabase(s.manipulator)
	if err != nil {
		return err
	}
	defer disco()

	return db.C(sessionsCollection).Insert(session)
}

// getOAuthSession loads the unified OAuth session payload.
func (s *store) getOAuthSession(code string) (*Session, error) {
	db, disco, err := manipmongo.GetDatabase(s.manipulator)
	if err != nil {
		return nil, err
	}
	defer disco()

	rec := &Session{}
	if err := db.C(sessionsCollection).Find(bson.M{"code": code, "invalidated": false}).One(rec); err != nil {
		return nil, err
	}
	if rec.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrAuthorizationCodeExpired
	}

	return rec, nil
}

// invalidateOAuthSession invalidates an OAuth session so the code cannot be reused.
func (s *store) invalidateOAuthSession(code string) error {
	db, disco, err := manipmongo.GetDatabase(s.manipulator)
	if err != nil {
		return err
	}
	defer disco()

	err = db.C(sessionsCollection).Update(bson.M{
		"code":        code,
		"invalidated": false,
	}, bson.M{
		"$set": bson.M{
			"invalidated": true,
			"expiresat":   time.Now().UTC(),
		},
	})
	if errors.Is(err, mgo.ErrNotFound) {
		return ErrAuthorizationCodeUsed
	}
	return err
}

func collectionIdentity(name string) elemental.Identity {
	return elemental.Identity{
		Name:     name,
		Category: name,
		Package:  "a3s",
	}
}
