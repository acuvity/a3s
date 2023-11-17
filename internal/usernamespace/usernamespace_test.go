package usernamespace

import (
	"reflect"
	"testing"
)

func Test_getEmailFromClaims(t *testing.T) {
	type args struct {
		claims []string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 bool
	}{
		{
			name: "no email",
			args: args{
				claims: []string{},
			},
			want:  "",
			want1: false,
		},
		{
			name: "email",
			args: args{
				claims: []string{"email=a@abc.com"},
			},
			want:  "a@abc.com",
			want1: true,
		},
		{
			name: "duplicate email",
			args: args{
				claims: []string{"email=b@abc.com", "email=a@abc.com"},
			},
			want:  "b@abc.com",
			want1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getEmailFromClaims(tt.args.claims)
			if got != tt.want {
				t.Errorf("getEmailFromClaims() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getEmailFromClaims() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_getAuthzClaims(t *testing.T) {
	type args struct {
		claims []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "no system claims",
			args: args{
				claims: []string{"source=none"},
			},
			want: []string{},
		},
		{
			name: "only email claims",
			args: args{
				claims: []string{"email=a@b.com"},
			},
			want: []string{"email=a@b.com"},
		},
		{
			name: "only authz claims",
			args: args{
				claims: []string{"@source:name=google-oidc", "@source:namespace=/", "email=a@b.com"},
			},
			want: []string{"@source:name=google-oidc", "@source:namespace=/", "email=a@b.com"},
		},
		{
			name: "all claims",
			args: args{
				claims: []string{"first-name=a", "family-name=b", "@source:name=google-oidc", "@source:namespace=/", "email=a@b.com"},
			},
			want: []string{"@source:name=google-oidc", "@source:namespace=/", "email=a@b.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAuthzClaims(tt.args.claims); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAuthzClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}
