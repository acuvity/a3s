package indexes

import (
	"encoding/json"
	"reflect"
	"testing"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	bson "go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongooptions "go.mongodb.org/mongo-driver/v2/mongo/options"
)

type comparableIndexModel struct {
	Name   string `json:"name"`
	Keys   bson.D `json:"keys"`
	Unique bool   `json:"unique"`
}

func comparableIndexes(models []mongo.IndexModel) []comparableIndexModel {
	out := make([]comparableIndexModel, 0, len(models))
	for _, model := range models {
		entry := comparableIndexModel{}
		if keys, ok := model.Keys.(bson.D); ok {
			entry.Keys = keys
		}
		if model.Options != nil {
			opts := &mongooptions.IndexOptions{}
			for _, apply := range model.Options.List() {
				if err := apply(opts); err != nil {
					continue
				}
			}
			if opts.Name != nil {
				entry.Name = *opts.Name
			}
			if opts.Unique != nil {
				entry.Unique = *opts.Unique
			}
		}
		out = append(out, entry)
	}
	return out
}

func indexModel(name string, unique bool, keys ...string) mongo.IndexModel {
	keyDoc := make(bson.D, 0, len(keys))
	for _, key := range keys {
		keyDoc = append(keyDoc, bson.E{Key: key, Value: int32(1)})
	}
	opts := mongooptions.Index().SetName(name)
	if unique {
		opts.SetUnique(true)
	}
	return mongo.IndexModel{Keys: keyDoc, Options: opts}
}

func TestGetIndexes(t *testing.T) {
	type args struct {
		model       elemental.ModelManager
		identity    elemental.Identity
		packageName string
	}
	tests := []struct {
		wantMIndexes map[elemental.Identity][]mongo.IndexModel
		args         args
		name         string
	}{
		{
			name: "all indexes",
			args: args{
				packageName: "a3s",
				identity:    api.AuthorizationIdentity,
				model:       api.Manager(),
			},
			wantMIndexes: map[elemental.Identity][]mongo.IndexModel{
				api.AuthorizationIdentity: {
					indexModel("shard_index_authorization_zone_zhash", true, "zone", "zhash"),
					indexModel("index_authorization_namespace", false, "namespace"),
					indexModel("index_authorization_namespace__id", false, "namespace", "_id"),
					indexModel("index_authorization_namespace_flattenedsubject_disabled", false, "namespace", "flattenedsubject", "disabled"),
					indexModel("index_authorization_namespace_flattenedsubject_propagate", false, "namespace", "flattenedsubject", "propagate"),
					indexModel("index_authorization_namespace_importlabel", false, "namespace", "importlabel"),
					indexModel("index_authorization_namespace_label", false, "namespace", "label"),
					indexModel("index_authorization_namespace_trustedissuers", false, "namespace", "trustedissuers"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMIndexes := GetIndexes(tt.args.packageName, tt.args.model)
			got := comparableIndexes(gotMIndexes[tt.args.identity])
			want := comparableIndexes(tt.wantMIndexes[tt.args.identity])
			if !reflect.DeepEqual(got, want) {
				d1, _ := json.MarshalIndent(got, "", "  ")
				d2, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("GetIndexes()\nEXPECTED:\n%s\nACTUAL:\n%s\n", d2, d1)
			}
		})
	}
}
