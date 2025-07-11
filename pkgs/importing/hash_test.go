package importing

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
)

func TestHash(t *testing.T) {
	type args struct {
		obj     Importable
		manager elemental.ModelManager
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1      string
		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"nil obj",
			func(*testing.T) args {
				return args{
					nil,
					nil,
				}
			},
			"",
			true,
			nil,
		},
		{
			"nil manager",
			func(*testing.T) args {
				return args{
					api.NewHTTPSource(),
					nil,
				}
			},
			"",
			true,
			nil,
		},
		{
			"basic",
			func(*testing.T) args {
				return args{
					api.NewHTTPSource(),
					api.Manager(),
				}
			},
			"30e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
		{
			"with nested object with explicit default value set",
			func(*testing.T) args {
				o := api.NewHTTPSource()
				o.Name = "name"
				o.Modifier = api.NewIdentityModifier()
				o.Modifier.Method = api.IdentityModifierMethodPOST
				return args{
					o,
					api.Manager(),
				}
			},
			"39373933393238343838353037323338393835e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
		{
			"with no nested object",
			func(*testing.T) args {
				o := api.NewHTTPSource()
				o.Name = "name"
				o.ImportHash = "h"
				o.ImportLabel = "l"
				return args{
					o,
					api.Manager(),
				}
			},
			"39373933393238343838353037323338393835e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
		{
			"with no nested object and ns",
			func(*testing.T) args {
				o := api.NewHTTPSource()
				o.Name = "name"
				o.ImportHash = "h"
				o.ImportLabel = "l"
				o.Namespace = "ns"
				return args{
					o,
					api.Manager(),
				}
			},
			"39353238373638333838383732323933323535e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1, err := Hash(tArgs.obj, tArgs.manager)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Hash got1 = %v, want1: %v", got1, tt.want1)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("Hash error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func Test_sanitize(t *testing.T) {
	type args struct {
		restName string
		obj      Importable
		manager  elemental.ModelManager
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1      map[string]any
		wantErr    bool
		inspectErr func(err error, t *testing.T) // use for more precise error evaluation after test
	}{
		{
			"basic without nested object",
			func(*testing.T) args {
				obj := api.NewHTTPSource()
				obj.Name = "name"
				obj.CA = "ca"
				obj.ImportHash = "should be removed"
				obj.ImportLabel = "should be removed"
				obj.CreateTime = time.Now()
				obj.Namespace = "should not be removed because its used to computed hash"
				return args{
					obj.Identity().Name,
					obj,
					api.Manager(),
				}
			},
			map[string]any{
				"name":      "name",
				"CA":        "ca",
				"namespace": "should not be removed because its used to computed hash",
			},
			false,
			nil,
		},
		{
			"with zero value nested object",
			func(*testing.T) args {
				obj := api.NewHTTPSource()
				obj.Name = "name"
				obj.CA = "ca"
				obj.ImportHash = "should be removed"
				obj.ImportLabel = "should be removed"
				obj.CreateTime = time.Now()
				obj.Namespace = "should not be removed because its used to computed hash"
				obj.Modifier = api.NewIdentityModifier()
				return args{
					obj.Identity().Name,
					obj,
					api.Manager(),
				}
			},
			map[string]any{
				"name":      "name",
				"CA":        "ca",
				"namespace": "should not be removed because its used to computed hash",
			},
			false,
			nil,
		},
		{
			"with non zero nested object",
			func(*testing.T) args {
				obj := api.NewHTTPSource()
				obj.Name = "name"
				obj.CA = "ca"
				obj.ImportHash = "should be removed"
				obj.ImportLabel = "should be removed"
				obj.CreateTime = time.Now()
				obj.Namespace = "should not be removed because its used to computed hash"
				obj.Modifier = api.NewIdentityModifier()
				obj.Modifier.Certificate = "cert"
				return args{
					obj.Identity().Name,
					obj,
					api.Manager(),
				}
			},
			map[string]any{
				"name":      "name",
				"CA":        "ca",
				"namespace": "should not be removed because its used to computed hash",
				"modifier": map[string]any{
					"certificate": "cert",
				},
			},
			false,
			nil,
		},
		{
			"with default enum",
			func(*testing.T) args {
				obj := api.NewLDAPSource()
				obj.Name = "name"
				obj.CA = "ca"
				obj.CreateTime = time.Now()
				obj.ImportHash = "should be removed"
				obj.ImportLabel = "should be removed"
				obj.Namespace = "should not be removed because its used to computed hash"
				obj.SecurityProtocol = api.LDAPSourceSecurityProtocolTLS
				return args{
					obj.Identity().Name,
					obj,
					api.Manager(),
				}
			},
			map[string]any{
				"name":      "name",
				"CA":        "ca",
				"namespace": "should not be removed because its used to computed hash",
			},
			false,
			nil,
		},
		{
			"with non default enum",
			func(*testing.T) args {
				obj := api.NewLDAPSource()
				obj.Name = "name"
				obj.CA = "ca"
				obj.ImportHash = "should be removed"
				obj.ImportLabel = "should be removed"
				obj.CreateTime = time.Now()
				obj.Namespace = "should not be removed because its used to computed hash"
				obj.SecurityProtocol = api.LDAPSourceSecurityProtocolInbandTLS
				return args{
					obj.Identity().Name,
					obj,
					api.Manager(),
				}
			},
			map[string]any{
				"name":             "name",
				"CA":               "ca",
				"securityProtocol": api.LDAPSourceSecurityProtocolInbandTLS,
				"namespace":        "should not be removed because its used to computed hash",
			},
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1, err := sanitize(tArgs.restName, tArgs.obj, tArgs.manager)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("sanitize got1 = %v, want1: %v", got1, tt.want1)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("sanitize error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func Test_cleanIrrelevantValues(t *testing.T) {
	type args struct {
		data     map[string]any
		template map[string]any
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 map[string]any
	}{
		{
			"empty",
			func(*testing.T) args {
				return args{
					map[string]any{},
					map[string]any{},
				}
			},
			map[string]any{},
		},
		{
			"basic",
			func(*testing.T) args {
				return args{
					map[string]any{
						"zero-string":          "",
						"default-string":       "default",
						"string":               "string",
						"other-string":         "other-string",
						"zero-string-array":    nil,
						"default-string-array": []string{"default"},
						"string-array":         []string{"string"},
						"other-string-array":   []string{"other-string"},
						"not-matching-type":    "a",
						"sub": map[string]any{
							"zero-string":          "",
							"default-string":       "default",
							"string":               "string",
							"other-string":         "other-string",
							"zero-string-array":    nil,
							"default-string-array": []string{"default"},
							"string-array":         []string{"string"},
							"other-string-array":   []string{"other-string"},
							"not-matching-type":    "a",
						},
						"not-matching-sub": map[string]any{"a": "a"},
						"equal-sub":        map[string]any{"a": "a"},
					},
					map[string]any{
						"default-string":       "default",
						"string":               "not-string",
						"default-string-array": []string{"default"},
						"string-array":         []string{"not-string"},
						"not-matching-type":    1,
						"sub": map[string]any{
							"default-string":       "default",
							"string":               "not-string",
							"default-string-array": []string{"default"},
							"string-array":         []string{"not-string"},
							"not-matching-type":    1,
						},
						"not-matching-sub": "a",
						"equal-sub":        map[string]any{"a": "a"},
					},
				}
			},
			map[string]any{
				"string":             "string",
				"other-string":       "other-string",
				"string-array":       []string{"string"},
				"other-string-array": []string{"other-string"},
				"not-matching-type":  "a",
				"sub": map[string]any{
					"not-matching-type":  "a",
					"string":             "string",
					"other-string":       "other-string",
					"string-array":       []string{"string"},
					"other-string-array": []string{"other-string"},
				},
				"not-matching-sub": map[string]any{"a": "a"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := cleanIrrelevantValues(tArgs.data, tArgs.template)

			if !reflect.DeepEqual(got1, tt.want1) {
				a, _ := json.MarshalIndent(got1, "", "  ")
				b, _ := json.MarshalIndent(tt.want1, "", "  ")
				t.Errorf("clean got1 = %s\nwant1: %s", string(a), string(b))
			}
		})
	}
}

func Test_hash(t *testing.T) {
	type args struct {
		data map[string]any
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1      string
		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"nil",
			func(*testing.T) args {
				return args{
					nil,
				}
			},
			"30e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
		{
			"basic map",
			func(*testing.T) args {
				return args{
					map[string]any{
						"a": true,
						"b": 1,
						"c": "c",
						"d": []string{"a", "b"},
						"e": []any{"a", "b"},
						"f": map[string]any{"a": "b"},
					},
				}
			},
			"36353939373434343439343034313732353632e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			false,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1, err := hash(tArgs.data)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("hash got1 = %v, want1: %v", got1, tt.want1)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("hash error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}
