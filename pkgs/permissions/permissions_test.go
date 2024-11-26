package permissions

import (
	"reflect"
	"testing"
)

func TestContains(t *testing.T) {

	type args struct {
		perms PermissionMap
		other PermissionMap
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"empty",
			args{
				PermissionMap{},
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
			},
			false,
		},
		{
			"equals",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
			},
			true,
		},
		{
			"less identities",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				PermissionMap{
					"r1": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"less permissions",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				PermissionMap{
					"r1": {"get": true},
					"r2": {"put": true},
				},
			},
			true,
		},
		{
			"more identities",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				PermissionMap{
					"r3": {"put": true},
				},
			},
			false,
		},
		{
			"more permissions",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"delete": true, "put": true},
				},
				PermissionMap{
					"r1": {"get": true, "post": true, "delete": true},
					"r2": {"delete": true, "put": true},
				},
			},
			false,
		},

		{
			"base contains *",
			args{
				PermissionMap{
					"*": {"get": true, "post": true},
				},
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base contains *,*",
			args{
				PermissionMap{
					"*": {"*": true},
				},
				PermissionMap{
					"r1": {"get": true, "post": true},
					"r2": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base contains * other contains *",
			args{
				PermissionMap{
					"r1": {"get": true, "post": true, "put": true, "delete": true},
				},
				PermissionMap{
					"r1": {"*": true},
				},
			},
			false,
		},
		{
			"base and other contains matching *",
			args{
				PermissionMap{
					"*": {"get": true, "post": true},
				},
				PermissionMap{
					"*": {"get": true, "post": true},
				},
			},
			true,
		},
		{
			"base and other contains * with base containing other's decorators",
			args{
				PermissionMap{
					"*": {"get": true, "post": true},
				},
				PermissionMap{
					"*": {"get": true},
				},
			},
			true,
		},
		{
			"base and other contains * with other have more decorators",
			args{
				PermissionMap{
					"*": {"get": true, "post": true},
				},
				PermissionMap{
					"*": {"get": true, "delete": true},
				},
			},
			false,
		},
		{
			"missing * in matching before star",
			args{
				PermissionMap{
					"*":  {"*": true},
					"r1": {"post": true},
				},
				PermissionMap{
					"r1": {"get": true},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.perms.Contains(tt.args.other); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIntersect(t *testing.T) {
	type args struct {
		permissions  PermissionMap
		restrictions PermissionMap
	}
	tests := []struct {
		name string
		args args
		want PermissionMap
	}{

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api2:get,post",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				PermissionMap{
					"api2": {"get": true, "post": true},
				},
			},
			PermissionMap{
				"api2": {"get": true, "post": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api1:get and api2:delete",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				PermissionMap{
					"api1": {"get": true},
					"api2": {"delete": true},
				},
			},
			PermissionMap{
				"api1": {"get": true},
				"api2": {"delete": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get,post,put,delete to api2:*",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true, "post": true, "put": true, "delete": true},
				},
				PermissionMap{
					"api2": {"*": true},
				},
			},
			PermissionMap{
				"api2": {"get": true, "post": true, "put": true, "delete": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to api2:get,post",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				PermissionMap{
					"api2": {"get": true, "post": true},
				},
			},
			PermissionMap{
				"api2": {"get": true, "post": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to api2:*",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				PermissionMap{
					"api2": {"*": true},
				},
			},
			PermissionMap{
				"api2": {"*": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:* to *:*",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"*": true},
				},
				PermissionMap{
					"*": {"*": true},
				},
			},
			PermissionMap{
				"api1": {"get": true, "post": true, "put": true, "delete": true},
				"api2": {"*": true},
			},
		},

		{
			"intersection of api1:get,post,put,delete and api2:get to *:get",
			args{
				PermissionMap{
					"api1": {"get": true, "post": true, "put": true, "delete": true},
					"api2": {"get": true},
				},
				PermissionMap{
					"*": {"get": true},
				},
			},
			PermissionMap{
				"api1": {"get": true},
				"api2": {"get": true},
			},
		},

		{
			"intersection of *:* to a1:*",
			args{
				PermissionMap{
					"*": {"*": true},
				},
				PermissionMap{
					"a1": {"*": true},
				},
			},
			PermissionMap{
				"a1": {"*": true},
			},
		},

		{
			"intersection of *:* to a1:get,put",
			args{
				PermissionMap{
					"*": {"*": true},
				},
				PermissionMap{
					"a1": {"get": true, "put": true},
				},
			},
			PermissionMap{
				"a1": {"get": true, "put": true},
			},
		},

		{
			"intersection of *:get,put to *:get",
			args{
				PermissionMap{
					"*": {"get": true, "put": true},
				},
				PermissionMap{
					"*": {"get": true},
				},
			},
			PermissionMap{
				"*": {"get": true},
			},
		},

		{
			"intersection of a1:get,put to non permitted a2:*",
			args{
				PermissionMap{
					"a1": {"get": true, "put": true},
				},
				PermissionMap{
					"a2": {"get": true},
				},
			},
			PermissionMap{},
		},

		{
			"intersection of a1:get,put a2:delete to *:get and a1:post and a2:delete",
			args{
				PermissionMap{
					"a1": {"get": true, "put": true},
					"a2": {"delete": true},
				},
				PermissionMap{
					"*":  {"get": true},
					"a1": {"post": true},
					"a2": {"delete": true},
				},
			},
			PermissionMap{
				"a1": {"get": true},
				"a2": {"delete": true},
			},
		},

		{
			"intersection of a1:get,put a2:delete to *:get and a1:post and a2:delete",
			args{
				PermissionMap{
					"a1": {"get": true, "put": true},
					"a2": {"get": true, "post": true},
				},
				PermissionMap{
					"*":  {"get": true},
					"a1": {"put": true},
					"a2": {"post": true},
				},
			},
			PermissionMap{
				"a1": {"get": true, "put": true},
				"a2": {"get": true, "post": true},
			},
		},

		{
			"nil base",
			args{
				nil,
				PermissionMap{
					"a2": {"get": true},
				},
			},
			PermissionMap{},
		},

		{
			"nil other",
			args{
				PermissionMap{
					"a2": {"get": true},
				},
				nil,
			},
			PermissionMap{},
		},

		{
			"both nil",
			args{
				nil,
				nil,
			},
			PermissionMap{},
		},

		{
			"empty base",
			args{
				PermissionMap{},
				PermissionMap{
					"a2": {"get": true},
				},
			},
			PermissionMap{},
		},

		{
			"empty other",
			args{
				PermissionMap{
					"a2": {"get": true},
				},
				PermissionMap{},
			},
			PermissionMap{},
		},

		{
			"both empty",
			args{
				PermissionMap{},
				PermissionMap{},
			},
			PermissionMap{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.permissions.Intersect(tt.args.restrictions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Intersect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAllowed(t *testing.T) {

	type args struct {
		perms     PermissionMap
		operation string
		resource  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"identity: *, perm: * -> create",
			args{
				PermissionMap{
					"*": {
						"*": true,
					},
				},
				"create",
				"toto",
			},
			true,
		},
		{
			"identity: *, perm: * -> update",
			args{
				PermissionMap{
					"*": {
						"*": true,
					},
				},
				"update",
				"toto",
			},
			true,
		},
		{
			"identity: targeted, perm: post -> create",
			args{
				PermissionMap{
					"toto": {
						"post": true,
					},
				},
				"post",
				"toto",
			},
			true,
		},
		{
			"identity: targeted, perm: post -> update",
			args{
				PermissionMap{
					"toto": {
						"put": true,
					},
				},
				"sleep",
				"toto",
			},
			false,
		},
		{
			"identity: *,targeted, perm: post,get -> create",
			args{
				PermissionMap{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				"post",
				"toto",
			},
			true,
		},
		{
			"identity: *,targeted, perm: post,get -> get",
			args{
				PermissionMap{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				"get",
				"toto",
			},
			true,
		},
		{
			"identity: *,targeted, perm: post,get -> update",
			args{
				PermissionMap{
					"*": {
						"post": true,
					},
					"toto": {
						"get": true,
					},
				},
				"eat",
				"toto",
			},
			false,
		},

		{
			"toto:get=false,post=true -> get toto -> false",
			args{
				PermissionMap{
					"toto": {
						"get":  false,
						"post": true,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"toto:get=false,post=true -> post toto -> true",
			args{
				PermissionMap{
					"toto": {
						"get":  false,
						"post": true,
					},
				},
				"post",
				"toto",
			},
			true,
		},
		{
			"toto:get=false,*=true -> get toto -> false",
			args{
				PermissionMap{
					"toto": {
						"*":   true,
						"get": false,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"toto:get=false,*=true -> post toto -> true",
			args{
				PermissionMap{
					"toto": {
						"*":   true,
						"get": false,
					},
				},
				"post",
				"toto",
			},
			true,
		},
		{
			"toto:get=true,*=false -> get toto -> false",
			args{
				PermissionMap{
					"toto": {
						"*":   false,
						"get": true,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"toto:get=true,*=false -> get toto -> true",
			args{
				PermissionMap{
					"toto": {
						"*":   false,
						"get": false,
					},
				},
				"post",
				"toto",
			},
			false,
		},

		{
			"*:*, toto:get=false -> get toto -> false",
			args{
				PermissionMap{
					"*": {
						"*": true,
					},
					"toto": {
						"get": false,
					},
				},
				"get",
				"toto",
			},
			false,
		},

		{
			"*:*=true toto:get=false -> post toto -> true",
			args{
				PermissionMap{
					"*": {
						"*": false,
					},
					"toto": {
						"get": true,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"*:post=true,get=true toto:get=false -> get toto -> false",
			args{
				PermissionMap{
					"*": {
						"post": true,
						"get":  true,
					},
					"toto": {
						"get": false,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"*:get=false, toto:get=true titi:get=true,post=true -> get toto -> false",
			args{
				PermissionMap{
					"*": {
						"get": false,
					},
					"toto": {
						"get": true,
					},
					"titi": {
						"get":  true,
						"post": true,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"*:get=false, toto:get=true titi:get=true,post=true -> get titi -> false",
			args{
				PermissionMap{
					"*": {
						"get": false,
					},
					"toto": {
						"get": true,
					},
					"titi": {
						"get":  true,
						"post": true,
					},
				},
				"get",
				"titi",
			},
			false,
		},
		{
			"*:get=false, toto:get=true titi:get=true,post=true -> post titi -> true",
			args{
				PermissionMap{
					"*": {
						"get": false,
					},
					"toto": {
						"get": true,
					},
					"titi": {
						"get":  true,
						"post": true,
					},
				},
				"post",
				"titi",
			},
			true,
		},
		{
			"*:*=true, toto:*=false -> get toto -> false",
			args{
				PermissionMap{
					"*": {
						"*": true,
					},
					"toto": {
						"*": false,
					},
				},
				"get",
				"toto",
			},
			false,
		},
		{
			"*:*=true, toto:*=false -> get titi -> true",
			args{
				PermissionMap{
					"*": {
						"*": true,
					},
					"toto": {
						"*": false,
					},
				},
				"get",
				"titi",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.perms.Allows(tt.args.operation, tt.args.resource); got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCopy(t *testing.T) {
	type args struct {
		perms PermissionMap
	}
	tests := []struct {
		name string
		args args
		want PermissionMap
	}{
		{
			"valid case",
			args{
				perms: PermissionMap{
					"forwarded": {
						"delete": true,
					},
					"other": {
						"get": true,
					},
				},
			},
			PermissionMap{
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
				perms: PermissionMap{},
			},
			PermissionMap{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.perms.Copy(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Copy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	type args struct {
		perms    []string
		targetID string
	}
	tests := []struct {
		name string
		args args
		want PermissionMap
	}{

		{
			"simple unique permission",
			args{
				[]string{
					"api1:get,post",
				},
				"",
			},
			PermissionMap{
				"api1": {"get": true, "post": true},
			},
		},
		{
			"simple double permissions",
			args{
				[]string{
					"api1:get,post",
					"api2:get",
				},
				"",
			},
			PermissionMap{
				"api1": {"get": true, "post": true},
				"api2": {"get": true},
			},
		},
		{
			"simple overlapping permissions",
			args{
				[]string{
					"api1:get,post",
					"api1:delete",
				},
				"",
			},
			PermissionMap{
				"api1": {"get": true, "post": true, "delete": true},
			},
		},
		{
			"check with empty targetID",
			args{
				[]string{
					"api1:get,post:",
					"api1:delete",
				},
				"",
			},
			PermissionMap{
				"api1": {"get": true, "post": true, "delete": true},
			},
		},
		{
			"check with matching targetID",
			args{
				[]string{
					"api1:get,post:xxx",
					"api1:delete",
				},
				"xxx",
			},
			PermissionMap{
				"api1": {"get": true, "post": true, "delete": true},
			},
		},
		{
			"check with on matching targetID and one not matching",
			args{
				[]string{
					"api1:get,post:yyy,xxx",
					"api1:delete",
				},
				"xxx",
			},
			PermissionMap{
				"api1": {"get": true, "post": true, "delete": true},
			},
		},
		{
			"check with not matching targetID",
			args{
				[]string{
					"api1:get,post:xxx",
					"api1:delete",
				},
				"zzz",
			},
			PermissionMap{
				"api1": {"delete": true},
			},
		},

		{
			"check with negative permission 1",
			args{
				[]string{
					"-api1:delete",
					"api1:get,post,delete",
				},
				"zzz",
			},
			PermissionMap{
				"api1": {"delete": false, "post": true, "get": true},
			},
		},
		{
			"check with negative permission 1.1",
			args{
				[]string{
					"-api1:delete",
					"api1:delete",
				},
				"zzz",
			},
			PermissionMap{
				"api1": {"delete": false},
			},
		},
		{
			"check with negative permission 1.2",
			args{
				[]string{
					"api1:delete",
					"-api1:delete",
				},
				"zzz",
			},
			PermissionMap{
				"api1": {"delete": false},
			},
		},
		{
			"check with negative permission 2",
			args{
				[]string{
					"*:*",
					"-api1:delete",
				},
				"zzz",
			},
			PermissionMap{
				"*":    {"*": true},
				"api1": {"delete": false},
			},
		},
		{
			"check with negative permission 2.2",
			args{
				[]string{
					"api1:delete,get,post",
					"-*:get,delete",
				},
				"zzz",
			},
			PermissionMap{
				"*":    {"get": false, "delete": false},
				"api1": {"delete": true, "get": true, "post": true},
			},
		},
		{
			"check with negative permission 2.3",
			args{
				[]string{
					"api1:delete,get,post",
					"api2:get,put",
					"-*:get,delete",
				},
				"zzz",
			},
			PermissionMap{
				"*":    {"get": false, "delete": false},
				"api1": {"delete": true, "post": true, "get": true},
				"api2": {"put": true, "get": true},
			},
		},
		{
			"check with negative permission 3",
			args{
				[]string{
					"*:*",
					"-*:delete",
				},
				"zzz",
			},
			PermissionMap{
				"*": {"*": true, "delete": false},
			},
		},
		{
			"check with negative permission 3.1",
			args{
				[]string{
					"-*:delete",
					"*:*",
				},
				"zzz",
			},
			PermissionMap{
				"*": {"*": true, "delete": false},
			},
		},
		{
			"check with negative permission 4",
			args{
				[]string{
					"*:delete",
					"-*:delete",
				},
				"zzz",
			},
			PermissionMap{
				"*": {"delete": false},
			},
		},
		{
			"check with negative permission 4.1",
			args{
				[]string{
					"-*:delete",
					"*:delete",
				},
				"zzz",
			},
			PermissionMap{
				"*": {"delete": false},
			},
		},
		{
			"check with negative permission 5",
			args{
				[]string{
					"*:delete,post",
					"-*:delete",
				},
				"zzz",
			},
			PermissionMap{
				"*": {"post": true, "delete": false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(tt.args.perms, tt.args.targetID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResolveRestrictions()\ngot  %v\nwant %v", got, tt.want)
			}
		})
	}
}
