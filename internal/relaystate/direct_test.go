package relaystate

import (
	"reflect"
	"testing"
)

func TestIsDirectCall(t *testing.T) {
	type args struct {
		relayState string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 bool
	}{
		{
			"empty",
			func(*testing.T) args { return args{relayState: ""} },
			false,
		},
		{
			"is",
			func(*testing.T) args { return args{relayState: "_direct"} },
			true,
		},
		{
			"not",
			func(*testing.T) args { return args{relayState: "coucou"} },
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := IsDirect(tArgs.relayState)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("IsDirectCall got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
