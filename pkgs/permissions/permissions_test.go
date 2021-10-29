package permissions

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/elemental"
)

func TestContains(t *testing.T) {

	type args struct {
		perms map[string]map[string]bool
		other map[string]map[string]bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"empty",
			args{
				map[string]map[string]bool{},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
			},
			false,
		},
		{
			"equals",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
			},
			true,
		},
		{
			"less identities",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"less permissions",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true},
					"r2": {"put": true},
				},
			},
			true,
		},
		{
			"more identities",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				map[string]map[string]bool{
					"r3": {"put": true},
				},
			},
			false,
		},
		{
			"more permissions",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true, "delete": true},
					"r2": {"delete": true, "put": true},
				},
			},
			false,
		},

		{
			"base contains *",
			args{
				map[string]map[string]bool{
					"*": {"get": true, "post": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base contains *,*",
			args{
				map[string]map[string]bool{
					"*": {"*": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true, "post": true},
					"r2": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base contains * other contains *",
			args{
				map[string]map[string]bool{
					"r1": {"get": true, "post": true, "put": true, "delete": true},
				},
				map[string]map[string]bool{
					"r1": {"*": true},
				},
			},
			false,
		},
		{
			"base and other contains matching *",
			args{
				map[string]map[string]bool{
					"*": {"get": true, "post": true},
				},
				map[string]map[string]bool{
					"*": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base and other contains * with base containing other's decorators",
			args{
				map[string]map[string]bool{
					"*": {"get": true, "post": true},
				},
				map[string]map[string]bool{
					"*": {"get": true},
				},
			},
			true,
		},
		{
			"base and other contains * with other have more decorators",
			args{
				map[string]map[string]bool{
					"*": {"get": true, "post": true},
				},
				map[string]map[string]bool{
					"*": {"get": true, "delete": true},
				},
			},
			false,
		},
		{
			"missing * in matching before star",
			args{
				map[string]map[string]bool{
					"*":  {"*": true},
					"r1": {"post": true},
				},
				map[string]map[string]bool{
					"r1": {"get": true},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.args.perms, tt.args.other); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIntersect(t *testing.T) {
	type args struct {
		permissions  map[string]map[string]bool
		restrictions map[string]map[string]bool
	}
	tests := []struct {
		name string
		args args
		want map[string]map[string]bool
	}{

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api2:get,post",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				map[string]map[string]bool{
					"api2": {"get": true, "post": true},
				},
			},
			map[string]map[string]bool{
				"api2": {"get": true, "post": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api1:get and api2:delete",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				map[string]map[string]bool{
					"api1": {"get": true},
					"api2": {"delete": true},
				},
			},
			map[string]map[string]bool{
				"api1": {"get": true},
				"api2": {"delete": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api2:*",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				map[string]map[string]bool{
					"api2": {"*": true},
				},
			},
			map[string]map[string]bool{
				"api2": {"get": true, "post": true, "put": true, "delete": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to api2:get,post",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				map[string]map[string]bool{
					"api2": {"get": true, "post": true},
				},
			},
			map[string]map[string]bool{
				"api2": {"get": true, "post": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to api2:*",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				map[string]map[string]bool{
					"api2": {"*": true},
				},
			},
			map[string]map[string]bool{
				"api2": {"*": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to *:*",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				map[string]map[string]bool{
					"*": {"*": true},
				},
			},
			map[string]map[string]bool{
				"api1": {"get": true, "post": true, "put": true, "delete": true},
				"api2": {"*": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get to *:get",
			args{
				map[string]map[string]bool{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true},
				},
				map[string]map[string]bool{
					"*": {"get": true},
				},
			},
			map[string]map[string]bool{
				"api1": {"get": true},
				"api2": {"get": true},
			},
		},

		{
			"intersection of *:* to a1:*",
			args{
				map[string]map[string]bool{
					"*": {"*": true},
				},
				map[string]map[string]bool{
					"a1": {"*": true},
				},
			},
			map[string]map[string]bool{
				"a1": {"*": true},
			},
		},

		{
			"intersection of *:* to a1:get,put",
			args{
				map[string]map[string]bool{
					"*": {"*": true},
				},
				map[string]map[string]bool{
					"a1": {"get": true, "put": true},
				},
			},
			map[string]map[string]bool{
				"a1": {"get": true, "put": true},
			},
		},

		{
			"intersection of *:get,put to *:get",
			args{
				map[string]map[string]bool{
					"*": {"get": true, "put": true},
				},
				map[string]map[string]bool{
					"*": {"get": true},
				},
			},
			map[string]map[string]bool{
				"*": {"get": true},
			},
		},

		{
			"intersection of a1:get,put to non permitted a2:*",
			args{
				map[string]map[string]bool{
					"a1": {"get": true, "put": true},
				},
				map[string]map[string]bool{
					"a2": {"get": true},
				},
			},
			map[string]map[string]bool{},
		},

		{
			"intersection of a1:get,put a2:delete to *:get and a1:post and a2:delete",
			args{
				map[string]map[string]bool{
					"a1": {"get": true, "put": true},
					"a2": {"delete": true},
				},
				map[string]map[string]bool{
					"*":  {"get": true},
					"a1": {"post": true},
					"a2": {"delete": true},
				},
			},
			map[string]map[string]bool{
				"a1": {"get": true},
				"a2": {"delete": true},
			},
		},

		{
			"intersection of a1:get,put a2:delete to *:get and a1:post and a2:delete",
			args{
				map[string]map[string]bool{
					"a1": {"get": true, "put": true},
					"a2": {"get": true, "post": true},
				},
				map[string]map[string]bool{
					"*":  {"get": true},
					"a1": {"put": true},
					"a2": {"post": true},
				},
			},
			map[string]map[string]bool{
				"a1": {"get": true, "put": true},
				"a2": {"get": true, "post": true},
			},
		},

		{
			"nil base",
			args{
				nil,
				map[string]map[string]bool{
					"a2": {"get": true},
				},
			},
			map[string]map[string]bool{},
		},

		{
			"nil other",
			args{
				map[string]map[string]bool{
					"a2": {"get": true},
				},
				nil,
			},
			map[string]map[string]bool{},
		},

		{
			"both nil",
			args{
				nil,
				nil,
			},
			map[string]map[string]bool{},
		},

		{
			"empty base",
			args{
				map[string]map[string]bool{},
				map[string]map[string]bool{
					"a2": {"get": true},
				},
			},
			map[string]map[string]bool{},
		},

		{
			"empty other",
			args{
				map[string]map[string]bool{
					"a2": {"get": true},
				},
				map[string]map[string]bool{},
			},
			map[string]map[string]bool{},
		},

		{
			"both empty",
			args{
				map[string]map[string]bool{},
				map[string]map[string]bool{},
			},
			map[string]map[string]bool{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Intersect(tt.args.permissions, tt.args.restrictions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Intersect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOperationToMethod(t *testing.T) {

	tests := map[string]struct {
		operation      elemental.Operation
		expectedMethod string
		expectedError  bool
	}{
		"should be able to handle elemental.OperationCreate": {
			operation:      elemental.OperationCreate,
			expectedMethod: strings.ToLower(http.MethodPost),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationDelete": {
			operation:      elemental.OperationDelete,
			expectedMethod: strings.ToLower(http.MethodDelete),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationUpdate": {
			operation:      elemental.OperationUpdate,
			expectedMethod: strings.ToLower(http.MethodPut),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationRetrieve": {
			operation:      elemental.OperationRetrieve,
			expectedMethod: strings.ToLower(http.MethodGet),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationRetrieveMany": {
			operation:      elemental.OperationRetrieveMany,
			expectedMethod: strings.ToLower(http.MethodGet),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationInfo": {
			operation:      elemental.OperationInfo,
			expectedMethod: strings.ToLower(http.MethodGet),
			expectedError:  false,
		},
		"should be able to handle elemental.OperationPatch": {
			operation:      elemental.OperationPatch,
			expectedMethod: strings.ToLower(http.MethodPut),
			expectedError:  false,
		},
		"should return error for unsupported operation": {
			operation:      elemental.Operation("unsupported_operation"),
			expectedMethod: "",
			expectedError:  true,
		},
	}

	Convey("OperationToMethod", t, FailureHalts, func() {
		for scenario, testCase := range tests {
			Convey(scenario, func() {
				method, err := OperationToMethod(testCase.operation)
				So(err != nil, ShouldEqual, testCase.expectedError)
				So(method, ShouldEqual, testCase.expectedMethod)
			})
		}
	})
}

func TestIsAllowed(t *testing.T) {

	type args struct {
		perms     map[string]map[string]bool
		operation elemental.Operation
		identity  elemental.Identity
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"identity: *, perm: * -> create",
			args{
				map[string]map[string]bool{
					"*": {
						"*": true,
					},
				},
				elemental.OperationCreate,
				elemental.MakeIdentity("toto", "totos"),
			},
			true,
		},
		{
			"identity: *, perm: * -> update",
			args{
				map[string]map[string]bool{
					"*": {
						"*": true,
					},
				},
				elemental.OperationUpdate,
				elemental.MakeIdentity("toto", "totos"),
			},
			true,
		},
		{
			"identity: targeted, perm: post -> create",
			args{
				map[string]map[string]bool{
					"toto": {
						"post": true,
					},
				},
				elemental.OperationCreate,
				elemental.MakeIdentity("toto", "totos"),
			},
			true,
		},
		{
			"identity: targeted, perm: post -> update",
			args{
				map[string]map[string]bool{
					"toto": {
						"post": true,
					},
				},
				elemental.OperationUpdate,
				elemental.MakeIdentity("toto", "totos"),
			},
			false,
		},
		{
			"identity: *,targeted, perm: post,get -> create",
			args{
				map[string]map[string]bool{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				elemental.OperationCreate,
				elemental.MakeIdentity("toto", "totos"),
			},
			true,
		},
		{
			"identity: *,targeted, perm: post,get -> get",
			args{
				map[string]map[string]bool{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				elemental.OperationRetrieve,
				elemental.MakeIdentity("toto", "totos"),
			},
			true,
		},
		{
			"identity: *,targeted, perm: post,get -> update",
			args{
				map[string]map[string]bool{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				elemental.OperationUpdate,
				elemental.MakeIdentity("toto", "totos"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowed(tt.args.perms, tt.args.operation, tt.args.identity); got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCopy(t *testing.T) {
	type args struct {
		perms map[string]map[string]bool
	}
	tests := []struct {
		name string
		args args
		want map[string]map[string]bool
	}{
		{
			"valid case",
			args{
				perms: map[string]map[string]bool{
					"forwarded": {
						"delete": true,
					},
					"other": {
						"get": true,
					},
				},
			},
			map[string]map[string]bool{
				"forwarded": {
					"delete": true,
				},
				"other": {
					"get": true,
				},
			},
		},
		{
			"empty case",
			args{
				perms: map[string]map[string]bool{},
			},
			map[string]map[string]bool{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Copy(tt.args.perms); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Copy() = %v, want %v", got, tt.want)
			}
		})
	}
}
