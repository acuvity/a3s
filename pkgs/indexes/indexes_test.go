package indexes

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/globalsign/mgo"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
)

func TestGetIndexes(t *testing.T) {
	type args struct {
		model       elemental.ModelManager
		identity    elemental.Identity
		packageName string
	}
	tests := []struct {
		wantMIndexes map[elemental.Identity][]mgo.Index
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
			wantMIndexes: map[elemental.Identity][]mgo.Index{
				api.AuthorizationIdentity: {
					{
						Name:       "shard_index_authorization_zone_zhash",
						Key:        []string{"zone", "zhash"},
						Background: true,
						Unique:     true,
					},
					{
						Name:       "index_authorization_namespace",
						Key:        []string{"namespace"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace__id",
						Key:        []string{"namespace", "_id"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace_flattenedsubject_disabled",
						Key:        []string{"namespace", "flattenedsubject", "disabled"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace_flattenedsubject_propagate",
						Key:        []string{"namespace", "flattenedsubject", "propagate"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace_importlabel",
						Key:        []string{"namespace", "importlabel"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace_label",
						Key:        []string{"namespace", "label"},
						Background: true,
					},
					{
						Name:       "index_authorization_namespace_trustedissuers",
						Key:        []string{"namespace", "trustedissuers"},
						Background: true,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if gotMIndexes := GetIndexes(tt.args.packageName, tt.args.model); !reflect.DeepEqual(gotMIndexes[tt.args.identity], tt.wantMIndexes[tt.args.identity]) {
				d1, _ := json.MarshalIndent(gotMIndexes[tt.args.identity], "", "  ")
				d2, _ := json.MarshalIndent(tt.wantMIndexes[tt.args.identity], "", "  ")
				t.Errorf("GetIndexes()\n"+
					"EXPECTED:\n"+
					"%s\n"+
					"ACTUAL:\n"+
					"%s\n",
					d2,
					d1,
				)
			}
		})
	}
}
