package processors

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.acuvity.ai/a3s/pkgs/token"
)

func TestNamespaceParticipationTokenValidityAfterNetwork(t *testing.T) {
	for _, name := range []string{"no-id", "no-iat", "no-exp", "future-iat", "expired", "expires-during-permissions"} {
		t.Run(name, func(t *testing.T) {
			f := participationAuth(t)
			now := time.Now()
			idt := &token.IdentityToken{Identity: []string{"role=enroller", "@source:type=test", "@issuer=test-issuer"}, RegisteredClaims: jwt.RegisteredClaims{ID: "test-id", Issuer: "test-issuer", Audience: jwt.ClaimStrings{"test-audience"}, IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}}
			switch name {
			case "no-id":
				idt.ID = ""
			case "no-iat":
				idt.IssuedAt = nil
			case "no-exp":
				idt.ExpiresAt = nil
			case "future-iat":
				idt.IssuedAt = jwt.NewNumericDate(now.Add(time.Hour))
			case "expired":
				idt.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second))
			case "expires-during-permissions":
				idt.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Second))
				f.retriever.afterPermissions = func() { time.Sleep(time.Until(idt.ExpiresAt.Time) + 10*time.Millisecond) }
			}
			j := jwt.NewWithClaims(jwt.SigningMethodES256, idt)
			j.Header["kid"] = f.kid
			bearer, err := j.SignedString(f.key)
			if err != nil {
				t.Fatal(err)
			}
			store := &participationStoreFixture{state: participationState(t)}
			p, err := NewNamespaceParticipationProcessor(store, f.auth)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ProcessCreate(participationContext(t, bearer, "ClaimEnrollment")); err == nil || store.gets != 0 || store.claims != 0 {
				t.Fatalf("invalid token reached storage: %v gets=%d claims=%d", err, store.gets, store.claims)
			}
		})
	}
}
