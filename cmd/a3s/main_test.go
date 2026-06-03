package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	bson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func assertMongoUserCommand(t *testing.T, command bson.D, operation string, roles bson.A) {
	t.Helper()

	if len(command) != 2 {
		t.Fatalf("expected 2 command fields, got %#v", command)
	}
	if command[0].Key != operation || command[0].Value != "worker" {
		t.Fatalf("unexpected command operation: %#v", command[0])
	}
	if command[1].Key != "roles" || len(command[1].Value.(bson.A)) != len(roles) {
		t.Fatalf("unexpected command roles: %#v", command[1])
	}
}

func indexOptions(t *testing.T, model mongo.IndexModel) *options.IndexOptions {
	t.Helper()

	if model.Options == nil {
		t.Fatalf("expected index options")
	}

	opts := &options.IndexOptions{}
	for _, apply := range model.Options.List() {
		if err := apply(opts); err != nil {
			t.Fatalf("unexpected option error: %v", err)
		}
	}
	return opts
}

func TestA3STTLIndexSpecs(t *testing.T) {
	specs := a3sTTLIndexSpecs()
	if len(specs) != 4 {
		t.Fatalf("expected 4 TTL index specs, got %#v", specs)
	}

	expected := []struct {
		identity elemental.Identity
		field    string
		name     string
		ttl      time.Duration
	}{
		{identity: elemental.MakeIdentity("oauth2cache", "oauth2cache"), field: "time", name: "index_expiration_exp", ttl: time.Minute},
		{identity: elemental.MakeIdentity("samlcache", "samlcache"), field: "time", name: "index_expiration_exp", ttl: time.Minute},
		{identity: specs[2].identity, field: "deletetime", name: "index_expiration_deletetime", ttl: 24 * time.Hour},
		{identity: specs[3].identity, field: "expiration", name: "index_revocation_expiration", ttl: time.Minute},
	}
	for i, spec := range specs {
		if spec.identity != expected[i].identity || spec.field != expected[i].field || spec.name != expected[i].name || spec.ttl != expected[i].ttl || spec.message == "" {
			t.Fatalf("unexpected spec %d: %#v", i, spec)
		}
	}
}

func TestTTLIndexModel(t *testing.T) {
	model := ttlIndexModel("expiration", "index_expiration", 2*time.Minute)

	keys, ok := model.Keys.(bson.D)
	if !ok {
		t.Fatalf("expected bson.D keys, got %T", model.Keys)
	}
	if len(keys) != 1 || keys[0].Key != "expiration" || keys[0].Value != 1 {
		t.Fatalf("unexpected index keys: %#v", keys)
	}

	opts := indexOptions(t, model)
	if opts.Name == nil || *opts.Name != "index_expiration" {
		t.Fatalf("unexpected index name: %#v", opts.Name)
	}
	if opts.ExpireAfterSeconds == nil || *opts.ExpireAfterSeconds != 120 {
		t.Fatalf("unexpected TTL seconds: %#v", opts.ExpireAfterSeconds)
	}
}

func TestEnsureTTLIndexesCallsEnsure(t *testing.T) {
	specs := []ttlIndexSpec{
		{identity: elemental.MakeIdentity("one", "ones"), field: "expires", name: "idx_one", ttl: time.Minute, message: "one failed"},
		{identity: elemental.MakeIdentity("two", "twos"), field: "deletes", name: "idx_two", ttl: 2 * time.Minute, message: "two failed"},
	}

	calls := 0
	err := ensureTTLIndexes(nil, specs, func(_ manipulate.Manipulator, identity elemental.Identity, models ...mongo.IndexModel) error {
		spec := specs[calls]
		calls++
		if len(models) != 1 {
			t.Fatalf("expected one index model, got %#v", models)
		}
		if identity != spec.identity {
			t.Fatalf("unexpected identity: %#v", identity)
		}
		model := models[0]
		keys := model.Keys.(bson.D)
		if len(keys) != 1 || keys[0].Key != spec.field || keys[0].Value != 1 {
			t.Fatalf("unexpected keys: %#v", keys)
		}
		opts := indexOptions(t, model)
		if opts.Name == nil || *opts.Name != spec.name {
			t.Fatalf("unexpected index name: %#v", opts.Name)
		}
		if opts.ExpireAfterSeconds == nil || *opts.ExpireAfterSeconds != int32(spec.ttl.Seconds()) {
			t.Fatalf("unexpected TTL: %#v", opts.ExpireAfterSeconds)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ensureTTLIndexes returned unexpected error: %v", err)
	}
	if calls != len(specs) {
		t.Fatalf("expected %d ensure calls, got %d", len(specs), calls)
	}
}

func TestEnsureTTLIndexesWrapsEnsureErrors(t *testing.T) {
	sentinel := errors.New("ensure failed")
	specs := []ttlIndexSpec{{identity: elemental.MakeIdentity("one", "ones"), field: "expires", name: "idx_one", ttl: time.Minute, message: "one failed"}}

	err := ensureTTLIndexes(nil, specs, func(manipulate.Manipulator, elemental.Identity, ...mongo.IndexModel) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "one failed") {
		t.Fatalf("expected wrapped ensure error, got %v", err)
	}
}

func TestFinishMongoCommand(t *testing.T) {
	info := mongoUsersInfo{}
	result := mongo.NewSingleResultFromDocument(bson.D{{Key: "users", Value: bson.A{bson.M{"user": "worker"}}}}, nil, nil)
	if err := finishMongoCommand(result, &info); err != nil {
		t.Fatalf("finishMongoCommand returned unexpected decode error: %v", err)
	}
	if len(info.Users) != 1 || info.Users[0]["user"] != "worker" {
		t.Fatalf("unexpected decoded users info: %#v", info)
	}

	if err := finishMongoCommand(mongo.NewSingleResultFromDocument(bson.D{{Key: "ok", Value: 1}}, nil, nil), nil); err != nil {
		t.Fatalf("finishMongoCommand returned unexpected command error: %v", err)
	}

	sentinel := errors.New("command failed")
	if err := finishMongoCommand(mongo.NewSingleResultFromDocument(bson.D{{Key: "ok", Value: 0}}, sentinel, nil), nil); !errors.Is(err, sentinel) {
		t.Fatalf("expected command error %v, got %v", sentinel, err)
	}
}

func TestRunMongoCommandRequiresDatabase(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected nil database panic")
		}
	}()
	_ = runMongoCommand(context.Background(), nil, bson.D{{Key: "ping", Value: 1}}, nil)
}

func TestMongoAccountRoles(t *testing.T) {
	roles := mongoAccountRoles()
	if len(roles) != 2 {
		t.Fatalf("expected readWrite and dbAdmin roles, got %#v", roles)
	}

	readWrite := roles[0].(bson.D)
	if readWrite[0].Key != "role" || readWrite[0].Value != "readWrite" || readWrite[1].Key != "db" || readWrite[1].Value != "a3s" {
		t.Fatalf("unexpected readWrite role: %#v", readWrite)
	}

	dbAdmin := roles[1].(bson.D)
	if dbAdmin[0].Key != "role" || dbAdmin[0].Value != "dbAdmin" || dbAdmin[1].Key != "db" || dbAdmin[1].Value != "a3s" {
		t.Fatalf("unexpected dbAdmin role: %#v", dbAdmin)
	}
}

func TestMongoUserCommandChoosesCreateOrUpdate(t *testing.T) {
	roles := mongoAccountRoles()

	assertMongoUserCommand(t, mongoUserCommand("worker", roles, nil), "createUser", roles)
	assertMongoUserCommand(t, mongoUserCommand("worker", roles, []bson.M{{"user": "worker"}}), "updateUser", roles)
}

func TestUpsertMongoUserWithRunnerCreatesMissingUser(t *testing.T) {
	roles := mongoAccountRoles()
	commands := []bson.D{}

	err := upsertMongoUserWithRunner("worker", roles, func(command bson.D, out any) error {
		commands = append(commands, command)
		if out != nil {
			out.(*mongoUsersInfo).Users = nil
		}
		return nil
	})
	if err != nil {
		t.Fatalf("upsertMongoUserWithRunner returned unexpected error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected usersInfo and createUser commands, got %#v", commands)
	}
	if commands[0][0].Key != "usersInfo" || commands[0][0].Value != "worker" {
		t.Fatalf("unexpected usersInfo command: %#v", commands[0])
	}
	assertMongoUserCommand(t, commands[1], "createUser", roles)
}

func TestUpsertMongoUserWithRunnerUpdatesExistingUser(t *testing.T) {
	roles := mongoAccountRoles()
	commands := []bson.D{}

	err := upsertMongoUserWithRunner("worker", roles, func(command bson.D, out any) error {
		commands = append(commands, command)
		if out != nil {
			out.(*mongoUsersInfo).Users = []bson.M{{"user": "worker"}}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("upsertMongoUserWithRunner returned unexpected error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected usersInfo and updateUser commands, got %#v", commands)
	}
	assertMongoUserCommand(t, commands[1], "updateUser", roles)
}

func TestUpsertMongoUserWithRunnerReturnsCommandErrors(t *testing.T) {
	roles := mongoAccountRoles()
	sentinel := errors.New("mongo command failed")

	if err := upsertMongoUserWithRunner("worker", roles, func(bson.D, any) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("expected usersInfo error %v, got %v", sentinel, err)
	}

	calls := 0
	err := upsertMongoUserWithRunner("worker", roles, func(command bson.D, out any) error {
		calls++
		if out != nil {
			out.(*mongoUsersInfo).Users = nil
			return nil
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected upsert error %v, got %v", sentinel, err)
	}
	if calls != 2 {
		t.Fatalf("expected two commands before upsert error, got %d", calls)
	}
}
