package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisAuthorizeContextKeyPrefix = "a3s:oauth:authorize-context:"
	redisSessionKeyPrefix          = "a3s:oauth:session:"
)

// redisStore is a Redis-backed persistence layer for OAuth-owned contexts and sessions.
type redisStore struct {
	client                  redis.UniversalClient
	invalidateSessionScript *redis.Script
}

// NewRedisStore returns a new Redis-backed OAuth store.
func NewRedisStore(client redis.UniversalClient) *redisStore {
	return &redisStore{
		client:                  client,
		invalidateSessionScript: redis.NewScript(redisInvalidateSessionLua),
	}
}

// Init preloads Lua scripts required by the Redis-backed store.
func (s *redisStore) Init() error {
	return s.invalidateSessionScript.Load(context.Background(), s.client).Err()
}

func (s *redisStore) createAuthorizeContext(authorizeContext *AuthorizeContext) error {
	payload, err := encodeRedisValue(authorizeContext)
	if err != nil {
		return err
	}

	ttl, err := ttlUntil(authorizeContext.ExpiresAtUnix)
	if err != nil {
		return err
	}

	return s.client.Set(context.Background(), redisAuthorizeContextKey(authorizeContext.ID), payload, ttl).Err()
}

func (s *redisStore) getAuthorizeContext(id string) (*AuthorizeContext, error) {
	data, err := s.client.Get(context.Background(), redisAuthorizeContextKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	out := &AuthorizeContext{}
	if err := decodeRedisValue(data, out); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *redisStore) createOAuthSession(session *Session) error {
	payload, err := encodeRedisValue(session)
	if err != nil {
		return err
	}

	ttl, err := ttlUntil(session.ExpiresAtUnix)
	if err != nil {
		return err
	}

	return s.client.Set(context.Background(), redisSessionKey(session.Code), payload, ttl).Err()
}

func (s *redisStore) getOAuthSession(code string) (*Session, error) {
	data, err := s.client.Get(context.Background(), redisSessionKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	out := &Session{}
	if err := decodeRedisValue(data, out); err != nil {
		return nil, err
	}
	if out.ExpiresAtUnix <= time.Now().Unix() {
		return nil, ErrAuthorizationCodeExpired
	}

	return out, nil
}

func (s *redisStore) invalidateOAuthSession(code string) error {
	result, err := s.invalidateSessionScript.Run(
		context.Background(),
		s.client,
		[]string{redisSessionKey(code)},
		time.Now().Unix(),
	).Int()
	if err != nil {
		return err
	}

	switch result {
	case 1:
		return nil
	case 0:
		return ErrAuthorizationCodeUsed
	case 2:
		return ErrNotFound
	case -1:
		return ErrAuthorizationCodeExpired
	default:
		return fmt.Errorf("oauthserver: unexpected redis invalidation result %d", result)
	}
}

func redisAuthorizeContextKey(id string) string {
	return redisAuthorizeContextKeyPrefix + id
}

func redisSessionKey(code string) string {
	return redisSessionKeyPrefix + code
}

func encodeRedisValue(value any) ([]byte, error) {
	return json.Marshal(value)
}

func decodeRedisValue(data []byte, out any) error {
	return json.Unmarshal(data, out)
}

func ttlUntil(expiration int64) (time.Duration, error) {
	ttl := time.Until(time.Unix(expiration, 0).UTC())
	if ttl <= 0 {
		return 0, fmt.Errorf("oauthserver: expiration %d is already expired", expiration)
	}

	return ttl, nil
}

const redisInvalidateSessionLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local payload = redis.call("GET", key)

if not payload then
	return 2
end

local session = cjson.decode(payload)

if session["invalidated"] then
	return 0
end

if tonumber(session["expiresatunix"]) <= now then
	return -1
end

session["invalidated"] = true

redis.call("SET", key, cjson.encode(session), "KEEPTTL")
return 1
`
