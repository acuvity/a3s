package processors

import (
	"reflect"
	"testing"
)

func Test_alignNamespacName(t *testing.T) {

	checkErr := func(want string) func(error, *testing.T) {
		return func(err error, t *testing.T) {
			if err.Error() != want {
				t.Logf("invalid error: got:\n%s\nwant:\n%s", err.Error(), want)
				t.Fail()
			}
		}
	}

	type args struct {
		name      string
		namespace string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1      string
		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"relative in /",
			func(t *testing.T) args { return args{"a", "/"} },
			"/a",
			false,
			nil,
		},
		{
			"relative in /a",
			func(t *testing.T) args { return args{"a", "/x"} },
			"/x/a",
			false,
			nil,
		},
		{
			"full in /",
			func(t *testing.T) args { return args{"/a", "/"} },
			"/a",
			false,
			nil,
		},
		{
			"full in /x",
			func(t *testing.T) args { return args{"/x/a", "/x"} },
			"/x/a",
			false,
			nil,
		},
		{
			"full in /x/y/x",
			func(t *testing.T) args { return args{"/x/y/z/a", "/x/y/z"} },
			"/x/y/z/a",
			false,
			nil,
		},

		// Negative
		{
			"empty in /",
			func(t *testing.T) args { return args{"", ""} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Empty namespace name"),
		},
		{
			"/ in empty",
			func(t *testing.T) args { return args{"/", ""} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: You cannot create the / namespace"),
		},
		{
			"/ in /",
			func(t *testing.T) args { return args{"/", "/"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: You cannot create the / namespace"),
		},
		{
			"/ in /a",
			func(t *testing.T) args { return args{"/", "/a"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: You cannot create the / namespace"),
		},
		{
			"/a/b/c in empty",
			func(t *testing.T) args { return args{"/a/b/c", ""} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Empty namespace"),
		},

		{
			"/a/b/c in /x/y/z",
			func(t *testing.T) args { return args{"/a/b/c", "/x/y/z"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Full namespace name must be prefixed with request namespace. got: /a/b"),
		},
		{
			"/x/y in /x/y/z",
			func(t *testing.T) args { return args{"/x/y", "/x/y/z"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Full namespace name must be prefixed with request namespace. got: /x"),
		},
		{
			"/x/y/z in /x",
			func(t *testing.T) args { return args{"/x/y/z", "/x"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Full namespace name must be prefixed with request namespace. got: /x/y"),
		},
		{
			"/x/y/ in /x",
			func(t *testing.T) args { return args{"/x/y/", "/x/y"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Namespace must not terminate with /"),
		},
		{
			"/x//y in /x",
			func(t *testing.T) args { return args{"/x//y", "/x"} },
			"",
			true,
			checkErr("error 422 (a3s): Validation Error: Namespace must not contain consecutive /"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1, err := alignNamespacName(tArgs.name, tArgs.namespace)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("alignNamespacName got1 = %v, want1: %v", got1, tt.want1)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("alignNamespacName error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}
