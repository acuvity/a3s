package tokenexchangeissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

type fakeValidator struct {
	claims map[string]any
	err    error
}

func (f *fakeValidator) ValidateAccessToken(_ context.Context, _ string) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

func TestErrTokenExchange(t *testing.T) {
	e := fmt.Errorf("boom")
	err := ErrTokenExchange{Err: e}
	if got, want := err.Error(), "token exchange error: boom"; got != want {
		t.Fatalf("unexpected error string: got %q want %q", got, want)
	}
	if err.Unwrap() != e {
		t.Fatalf("unexpected unwrap error: got %v want %v", err.Unwrap(), e)
	}
}

func TestNewTokenExchangeIssuer(t *testing.T) {
	iss := newTokenExchangeIssuer()
	if got, want := iss.Issue().Source.Type, "tokenexchange"; got != want {
		t.Fatalf("unexpected source type: got %q want %q", got, want)
	}
}

func TestFromTokenValidation(t *testing.T) {
	iss := newTokenExchangeIssuer()

	err := iss.fromToken(context.Background(), nil, "token")
	if err == nil {
		t.Fatalf("expected error with nil validator")
	}

	err = iss.fromToken(context.Background(), &fakeValidator{}, "")
	if err == nil {
		t.Fatalf("expected error with missing token")
	}

	err = iss.fromToken(context.Background(), &fakeValidator{err: fmt.Errorf("broken")}, "token")
	if err == nil {
		t.Fatalf("expected error with validator error")
	}

	err = iss.fromToken(context.Background(), &fakeValidator{claims: map[string]any{"sub": "alice"}}, "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, claim := range iss.Issue().Identity {
		if claim == "sub=alice" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing expected claim sub=alice: got %v", iss.Issue().Identity)
	}
}

func TestComputeTokenExchangeClaims(t *testing.T) {
	type args struct {
		claims map[string]any
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 []string
	}{
		{
			"standard",
			func(*testing.T) args {
				return args{claims: map[string]any{
					"sub":   "alice",
					"ten":   991033585.0,
					"roles": []any{"admin", "dev"},
					"@iss":  "issuer",
					"act":   []string{"read"},
					"exp":   1771184926.0,
					"iat":   json.Number("1771170526"),
					"profile": map[string]any{
						"alias":     "ebirger@proofpoint.com",
						"firstName": "Eyal",
						"lastName":  "Birger",
					},
				}}
			},
			[]string{
				"@org=ebirger",
				"act=read",
				"email=ebirger@proofpoint.com",
				"exp=1771184926",
				"iat=1771170526",
				"iss=issuer",
				"profile.alias=ebirger@proofpoint.com",
				"profile.firstName=Eyal",
				"profile.lastName=Birger",
				"roles=admin",
				"roles=dev",
				"sub=alice",
				"ten=991033585",
			},
		},
		{
			"fallback org from email",
			func(*testing.T) args {
				return args{claims: map[string]any{
					"sub":   "alice",
					"email": "ebirger@proofpoint.com",
				}}
			},
			[]string{
				"@org=ebirger",
				"email=ebirger@proofpoint.com",
				"sub=alice",
			},
		},
		{
			"prefer explicit org over email fallback",
			func(*testing.T) args {
				return args{claims: map[string]any{
					"sub":   "alice",
					"email": "ebirger@proofpoint.com",
					"org":   "acuvity.ai",
				}}
			},
			[]string{
				"@org=acuvity.ai",
				"email=ebirger@proofpoint.com",
				"org=acuvity.ai",
				"sub=alice",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := computeTokenExchangeClaims(tArgs.claims)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeTokenExchangeClaims got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
