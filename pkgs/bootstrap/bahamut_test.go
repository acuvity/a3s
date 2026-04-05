package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

type testPubSubClient struct{}

func (testPubSubClient) Publish(*bahamut.Publication, ...bahamut.PubSubOptPublish) error { return nil }
func (testPubSubClient) Subscribe(chan *bahamut.Publication, chan error, string, ...bahamut.PubSubOptSubscribe) func() {
	return func() {}
}
func (testPubSubClient) Connect(context.Context) error { return nil }
func (testPubSubClient) Disconnect() error             { return nil }

type testIdentifiable struct {
	identity elemental.Identity
	id       string
}

func (t *testIdentifiable) Identity() elemental.Identity { return t.identity }
func (t *testIdentifiable) Identifier() string           { return t.id }
func (t *testIdentifiable) SetIdentifier(id string)      { t.id = id }
func (t *testIdentifiable) Version() int                 { return 0 }

type testModelManager struct{}

func (testModelManager) Identifiable(identity elemental.Identity) elemental.Identifiable {
	return &testIdentifiable{identity: identity}
}
func (testModelManager) SparseIdentifiable(elemental.Identity) elemental.SparseIdentifiable {
	return nil
}
func (testModelManager) IdentifiableFromString(string) elemental.Identifiable { return nil }
func (testModelManager) Identifiables(elemental.Identity) elemental.Identifiables {
	return nil
}
func (testModelManager) SparseIdentifiables(elemental.Identity) elemental.SparseIdentifiables {
	return nil
}
func (testModelManager) IdentifiablesFromString(string) elemental.Identifiables { return nil }
func (testModelManager) IdentityFromName(string) elemental.Identity             { return elemental.Identity{} }
func (testModelManager) IdentityFromCategory(string) elemental.Identity         { return elemental.Identity{} }
func (testModelManager) IdentityFromAlias(string) elemental.Identity            { return elemental.Identity{} }
func (testModelManager) IdentityFromAny(string) elemental.Identity              { return elemental.Identity{} }
func (testModelManager) Indexes(elemental.Identity) [][]string                  { return nil }
func (testModelManager) Relationships() elemental.RelationshipsRegistry {
	return elemental.RelationshipsRegistry{}
}
func (testModelManager) AllIdentities() []elemental.Identity { return nil }
func (testModelManager) DetachedFromString(string) any       { return nil }

func TestConfigureBahamutWithMinimalConfig(t *testing.T) {
	opts := ConfigureBahamut(context.Background(), struct{}{}, testPubSubClient{}, nil, nil, nil, nil, nil)
	if len(opts) != 8 {
		t.Fatalf("expected 8 default options, got %d", len(opts))
	}
}

func TestConfigureBahamutWithOptionalSettings(t *testing.T) {
	cfg := struct {
		conf.APIServerConf
		conf.HealthConfiguration
		conf.ProfilingConf
		conf.RateLimitingConf
		conf.HTTPTimeoutsConf
		conf.NATSPublisherConf
	}{
		APIServerConf: conf.APIServerConf{
			ListenAddress:         ":8443",
			MaxConnections:        123,
			CORSDefaultOrigin:     "https://app.example.com",
			CORSAdditionalOrigins: []string{"https://admin.example.com"},
		},
		HealthConfiguration: conf.HealthConfiguration{
			EnableHealth:        true,
			HealthListenAddress: ":9000",
		},
		ProfilingConf: conf.ProfilingConf{
			ProfilingEnabled:       true,
			ProfilingListenAddress: ":6060",
		},
		RateLimitingConf: conf.RateLimitingConf{
			RateLimitingEnabled: true,
			RateLimitingRPS:     12,
			RateLimitingBurst:   34,
		},
		HTTPTimeoutsConf: conf.HTTPTimeoutsConf{
			TimeoutRead:  time.Second,
			TimeoutWrite: 2 * time.Second,
			TimeoutIdle:  3 * time.Second,
		},
		NATSPublisherConf: conf.NATSPublisherConf{
			NATSPublishTopic: "events",
		},
	}

	opts := ConfigureBahamut(context.Background(), cfg, testPubSubClient{}, nil, nil, nil, nil, nil)
	if len(opts) != 18 {
		t.Fatalf("expected 18 options with optional settings enabled, got %d", len(opts))
	}
}

func TestMakeBahamutGatewayNotifier(t *testing.T) {
	if opts := MakeBahamutGatewayNotifier(context.Background(), testPubSubClient{}, "a3s", "", "127.0.0.1:8443"); opts != nil {
		t.Fatalf("expected no notifier options when no topic is configured")
	}

	opts := MakeBahamutGatewayNotifier(context.Background(), testPubSubClient{}, "a3s", "gateway.topic", "127.0.0.1:8443")
	if len(opts) != 2 {
		t.Fatalf("expected 2 notifier options, got %d", len(opts))
	}
}

func TestGetPublicEndpoint(t *testing.T) {
	endpoint, err := GetPublicEndpoint("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("GetPublicEndpoint returned unexpected error: %v", err)
	}
	if !strings.HasSuffix(endpoint, ":8443") {
		t.Fatalf("expected endpoint %q to preserve the listen port", endpoint)
	}

	if _, err := GetPublicEndpoint("bad-listen-address"); err == nil {
		t.Fatalf("expected invalid listen address to return an error")
	}
}

func TestMakeIdentifiableRetriever(t *testing.T) {
	manipulator := maniptest.NewTestManipulator()
	manipulator.MockRetrieve(t, func(_ manipulate.Context, object elemental.Identifiable) error {
		if object.Identity() != elemental.MakeIdentity("widget", "widgets") {
			t.Fatalf("unexpected identity: %+v", object.Identity())
		}
		if object.Identifier() != "object-id" {
			t.Fatalf("expected object identifier to be propagated before retrieval")
		}
		return nil
	})

	retriever := MakeIdentifiableRetriever(manipulator, testModelManager{})
	obj, err := retriever(&elemental.Request{
		Identity: elemental.MakeIdentity("widget", "widgets"),
		ObjectID: "object-id",
	})
	if err != nil {
		t.Fatalf("MakeIdentifiableRetriever returned unexpected error: %v", err)
	}
	if obj.Identifier() != "object-id" {
		t.Fatalf("expected retrieved object identifier to be preserved")
	}
}

func TestMakePublishHandler(t *testing.T) {
	handler := MakePublishHandler([]elemental.Identity{elemental.MakeIdentity("excluded", "excluded")})

	publish, err := handler.ShouldPublish(&elemental.Event{Identity: "excluded"})
	if err != nil {
		t.Fatalf("ShouldPublish returned unexpected error: %v", err)
	}
	if publish {
		t.Fatalf("expected excluded identity to be filtered out")
	}

	publish, err = handler.ShouldPublish(&elemental.Event{Identity: "included"})
	if err != nil {
		t.Fatalf("ShouldPublish returned unexpected error: %v", err)
	}
	if !publish {
		t.Fatalf("expected non-excluded identity to be published")
	}
}
