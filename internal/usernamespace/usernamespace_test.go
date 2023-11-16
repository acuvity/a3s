package usernamespace

import "testing"

func Test_getEmailClaim(t *testing.T) {
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
			got, got1 := getEmailClaim(tt.args.claims)
			if got != tt.want {
				t.Errorf("getEmailClaim() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getEmailClaim() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
