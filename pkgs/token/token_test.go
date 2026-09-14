package token

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/tg/tglib"
)

func getECCert() (*x509.Certificate, crypto.PrivateKey) {

	certBlock, keyBlock, err := tglib.Issue(pkix.Name{})
	if err != nil {
		panic(err)
	}

	cert, err := tglib.ParseCertificate(pem.EncodeToMemory(certBlock))
	if err != nil {
		panic(err)
	}

	key, err := tglib.PEMToKey(keyBlock)
	if err != nil {
		panic(err)
	}

	return cert, key
}

func TestNewIdentityToken(t *testing.T) {

	Convey("Given I create a new Midgard claims", t, func() {

		c := NewIdentityToken(Source{
			Type:      "mtls",
			Namespace: "/my/ns",
			Name:      "mysource",
		})

		So(c.Identity, ShouldBeNil)
		So(c.Source.Type, ShouldEqual, "mtls")
		So(c.Source.Namespace, ShouldEqual, "/my/ns")
		So(c.Source.Name, ShouldEqual, "mysource")

		So(c.Map(), ShouldResemble, map[string][]string{})
		c.Identity = []string{"a=b", "b=c", "b=d"}
		So(c.Map(), ShouldResemble, map[string][]string{"a": {"b"}, "b": {"c", "d"}})
	})
}

func TestIdentityToken_JSON(t *testing.T) {

	Convey("Given a fully populated IdentityToken", t, func() {

		token1 := &IdentityToken{
			Identity: []string{"org=a3s.com", "orgunit=admin"},
			Refresh:  true,
			Opaque:   map[string]string{"key": "value"},
			Restrictions: &permissions.Restrictions{
				Namespace:   "/the/ns",
				Networks:    []string{"10.0.0.0/24"},
				Permissions: []string{"dog:get,put"},
			},
			Source: Source{
				Type:      "certificate",
				Namespace: "/my/ns",
				Name:      "mysource",
			},
			OAuthApplication: OAuthApplication{
				ID:        "oauthapp-id",
				Namespace: "/oauth/ns",
				Name:      "oauthapp-name",
			},
			OAuthClient: OAuthClient{
				ClientID:  "oauthclient-id",
				Namespace: "/oauthclient/ns",
			},
		}
		token1.ID = "token-id"
		token1.Issuer = "iss"
		token1.Audience = jwt.ClaimStrings{"aud"}
		token1.IssuedAt = jwt.NewNumericDate(time.Now().Truncate(time.Second))
		token1.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Second).Truncate(time.Second))

		Convey("Marshaling it should produce the expected JSON keys", func() {

			d, err := json.Marshal(token1)
			So(err, ShouldBeNil)

			var m map[string]any
			So(json.Unmarshal(d, &m), ShouldBeNil)

			So(m, ShouldContainKey, "identity")
			So(m, ShouldContainKey, "refresh")
			So(m, ShouldContainKey, "opaque")
			So(m, ShouldContainKey, "restrictions")
			So(m, ShouldContainKey, "source")
			So(m, ShouldContainKey, "oauthApplication")
			So(m, ShouldContainKey, "oauthClient")
			So(m, ShouldContainKey, "jti")
			So(m, ShouldContainKey, "iss")
			So(m, ShouldContainKey, "aud")
			So(m, ShouldContainKey, "iat")
			So(m, ShouldContainKey, "exp")

			So(m["oauthClient"], ShouldResemble, map[string]any{
				"clientID":  "oauthclient-id",
				"namespace": "/oauthclient/ns",
			})
			So(m["oauthApplication"], ShouldResemble, map[string]any{
				"ID":        "oauthapp-id",
				"namespace": "/oauth/ns",
				"name":      "oauthapp-name",
			})
		})

		Convey("Marshaling then unmarshaling it should round trip all fields", func() {

			d, err := json.Marshal(token1)
			So(err, ShouldBeNil)

			token2 := &IdentityToken{}
			So(json.Unmarshal(d, token2), ShouldBeNil)

			So(token2, ShouldResemble, token1)
		})
	})

	Convey("Given an IdentityToken with zero-value OAuthApplication and OAuthClient", t, func() {

		token1 := &IdentityToken{
			Source: Source{
				Type: "certificate",
			},
		}

		Convey("Marshaling it should omit the oauthapplication and oauthClient keys", func() {

			d, err := json.Marshal(token1)
			So(err, ShouldBeNil)

			var m map[string]any
			So(json.Unmarshal(d, &m), ShouldBeNil)

			So(m, ShouldNotContainKey, "oauthApplication")
			So(m, ShouldNotContainKey, "oauthClient")
		})
	})
}

func TestParse(t *testing.T) {

	Convey("Given I create an IdentityToken", t, func() {

		cert, key := getECCert()

		token1 := NewIdentityToken(Source{
			Type:      "certificate",
			Namespace: "/my/ns",
			Name:      "mysource",
		})

		token1.Source.Type = "certificate"
		token1.Source.Namespace = "/my/ns"
		token1.Source.Name = "mysource"
		token1.OAuthApplication = OAuthApplication{
			ID:        "oauthapp-id",
			Namespace: "/oauth/ns",
			Name:      "oauthapp-name",
		}
		token1.OAuthClient = OAuthClient{
			ClientID:  "oauthclient-id",
			Namespace: "/oauthclient/ns",
		}
		token1.Identity = []string{
			"org=a3s.com",
			"orgunit=admin",
			"commonname=joe",
		}

		keychain := NewJWKS()
		_ = keychain.Append(cert)

		kid := Fingerprint(cert)

		token, err := token1.JWT(key, kid, "iss", jwt.ClaimStrings{"aud"}, time.Now().Add(10*time.Second), nil)
		So(err, ShouldBeNil)

		Convey("Calling JWT with a missing source type should fail", func() {
			token1.Source.Type = ""
			_, err := token1.JWT(key, "kid", "iss", jwt.ClaimStrings{"aud"}, time.Now().Add(10*time.Second), nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "invalid identity token: missing source type")
		})

		Convey("Calling JWT using cloaking", func() {
			token2, err := token1.JWT(key, kid, "iss", jwt.ClaimStrings{"aud"}, time.Now().Add(10*time.Second), []string{"org="})
			So(err, ShouldBeNil)
			token3, err := Parse(token2, keychain, "iss", "aud")
			So(err, ShouldBeNil)
			So(token3.Identity, ShouldResemble, []string{
				"@issuer=iss",
				"@oauthapp:id=oauthapp-id",
				"@oauthapp:name=oauthapp-name",
				"@oauthapp:namespace=/oauth/ns",
				"@oauthclient:clientid=oauthclient-id",
				"@oauthclient:namespace=/oauthclient/ns",
				"@source:name=mysource",
				"@source:namespace=/my/ns",
				"@source:type=certificate",
				"org=a3s.com",
			})
		})

		Convey("When I call Parse using the correct signer certificate", func() {

			token2, err := Parse(token, keychain, "iss", "aud")

			So(err, ShouldBeNil)
			So(token2.Source.Type, ShouldEqual, "certificate")
			So(token2.OAuthApplication, ShouldResemble, OAuthApplication{
				ID:        "oauthapp-id",
				Namespace: "/oauth/ns",
				Name:      "oauthapp-name",
			})
			So(token2.OAuthClient, ShouldResemble, OAuthClient{
				ClientID:  "oauthclient-id",
				Namespace: "/oauthclient/ns",
			})
			So(token2.Issuer, ShouldEqual, "iss")
			So(token2.Audience, ShouldResemble, jwt.ClaimStrings{"aud"})
			So(token2.ExpiresAt, ShouldResemble, token1.ExpiresAt)
			So(token2.IssuedAt, ShouldResemble, token1.IssuedAt)
			So(token2.Identity, ShouldResemble, []string{
				"@issuer=iss",
				"@oauthapp:id=oauthapp-id",
				"@oauthapp:name=oauthapp-name",
				"@oauthapp:namespace=/oauth/ns",
				"@oauthclient:clientid=oauthclient-id",
				"@oauthclient:namespace=/oauthclient/ns",
				"@source:name=mysource",
				"@source:namespace=/my/ns",
				"@source:type=certificate",
				"commonname=joe",
				"org=a3s.com",
				"orgunit=admin",
			})
		})

		Convey("When I call Parse using the wrong issuer", func() {

			token2, err := Parse(token, keychain, "iss2", "aud")

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to parse jwt: token has invalid claims: token has invalid issuer")
		})

		Convey("When I call Parse on a token missing the @source:type claim", func() {

			// Overwrite the test token
			claims := jwt.NewWithClaims(
				jwt.SigningMethodES256,
				jwt.MapClaims{
					"iss": "iss2",
				},
			)
			claims.Header["kid"] = kid

			token, _ := claims.SignedString(key)

			token2, err := Parse(token, keychain, "iss2", "")

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "invalid token: missing @source:type in identity claims")
		})
		Convey("When I call Parse using the wrong audience", func() {

			token2, err := Parse(token, keychain, "iss", "aud2")

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to parse jwt: token has invalid claims: token has invalid audience")
		})

		Convey("When I call Parse using the wrong signer certificate", func() {

			cert2, _ := getECCert()
			keychain2 := NewJWKS()
			_ = keychain2.Append(cert2)
			token2, err := Parse(token, keychain2, "iss", "aud")

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, fmt.Sprintf("unable to parse jwt: token is unverifiable: error while executing keyfunc: unable to find kid '%s': kid not found in JWKS", kid))
		})

		Convey("When I call Parse using a wrong asigning method", func() {

			token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6IlZpbmNlIiwiaWR0IjpbIkBzb3VyY2U9YS1zb3VyY2UiLCJAbmFtZXNwYWNlPS9hL25hbWVzcGFjZSIsInVzZXJuYW1lPWpvZSIsInRlYW09cmVkIl0sImF1ZCI6Imh0dHBzOi8vYTNzLmNvbSIsImlhdCI6MTU0ODc5MDMwMCwiaXNzIjoiaHR0cHM6Ly9hM3MuY29tIn0.5PYuuULqrMArgdxq5eKSImsNskobw528Gr8Xe7HgPFs"
			token2, err := Parse(token, keychain, "iss", "aud")

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to parse jwt: token is unverifiable: error while executing keyfunc: unexpected signing method: HS256")
		})
	})
}

func TestParseUnverified(t *testing.T) {

	Convey("Given I create an IdentityToken", t, func() {

		cert, key := getECCert()

		token1 := NewIdentityToken(Source{
			Type:      "certificate",
			Namespace: "/my/ns",
			Name:      "mysource",
		})

		token1.ExpiresAt = jwt.NewNumericDate(time.Now().Add(1 * time.Minute)) // we check that ParseUnverified does not actually verifies.
		token1.Source.Type = "certificate"
		token1.Source.Namespace = "/my/ns"
		token1.Source.Name = "mysource"
		token1.OAuthApplication = OAuthApplication{
			ID:        "oauthapp-id",
			Namespace: "/oauth/ns",
			Name:      "oauthapp-name",
		}
		token1.OAuthClient = OAuthClient{
			ClientID:  "oauthclient-id",
			Namespace: "/oauthclient/ns",
		}
		token1.Identity = []string{
			"org=a3s.com",
			"orgunit=admin",
			"commonname=joe",
		}

		keychain := NewJWKS()
		_ = keychain.Append(cert)

		kid := Fingerprint(cert)

		token, err := token1.JWT(key, kid, "iss", jwt.ClaimStrings{"aud"}, time.Now().Add(10*time.Second), nil)
		So(err, ShouldBeNil)

		Convey("When I call ParseUnverified", func() {

			token2, err := ParseUnverified(token)

			So(err, ShouldBeNil)
			So(token2.Source.Type, ShouldEqual, "certificate")
			So(token2.OAuthApplication, ShouldResemble, OAuthApplication{
				ID:        "oauthapp-id",
				Namespace: "/oauth/ns",
				Name:      "oauthapp-name",
			})
			So(token2.OAuthClient, ShouldResemble, OAuthClient{
				ClientID:  "oauthclient-id",
				Namespace: "/oauthclient/ns",
			})
			So(token2.Issuer, ShouldEqual, "iss")
			So(token2.Audience, ShouldResemble, jwt.ClaimStrings{"aud"})
			So(token2.ExpiresAt, ShouldResemble, token1.ExpiresAt)
			So(token2.IssuedAt, ShouldResemble, token1.IssuedAt)
			So(token2.Identity, ShouldResemble, []string{
				"@issuer=iss",
				"@oauthapp:id=oauthapp-id",
				"@oauthapp:name=oauthapp-name",
				"@oauthapp:namespace=/oauth/ns",
				"@oauthclient:clientid=oauthclient-id",
				"@oauthclient:namespace=/oauthclient/ns",
				"@source:name=mysource",
				"@source:namespace=/my/ns",
				"@source:type=certificate",
				"commonname=joe",
				"org=a3s.com",
				"orgunit=admin",
			})
		})

		Convey("When I call ParseUnverified on a token missing the @source:type claim", func() {

			// Overwrite the test token
			claims := jwt.NewWithClaims(
				jwt.SigningMethodES256,
				jwt.MapClaims{
					"iss": "iss2",
				},
			)
			claims.Header["kid"] = kid

			token, _ := claims.SignedString(key)
			token2, err := ParseUnverified(token)

			So(token2, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "invalid token: missing @source:type in identity claims")
		})

		Convey("Passing a badly formatted token should error", func() {

			token, err := ParseUnverified("this is not a token")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to parse unverified jwt: token is malformed: token contains an invalid number of segments")
			So(token, ShouldBeNil)
		})
	})
}

func TestIdentityToken_Restrict(t *testing.T) {
	type args struct {
		restrictions permissions.Restrictions
	}
	tests := []struct {
		name    string
		init    func(t *testing.T) *IdentityToken
		inspect func(r *IdentityToken, t *testing.T) //inspects receiver after test run

		args func(t *testing.T) args

		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"empty existing restrictions, zero requested",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: nil,
				}
			},
			func(r *IdentityToken, t *testing.T) {
				if r.Restrictions != nil {
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{},
				}
			},
			false,
			nil,
		},
		{
			"zero existing restrictions, zero requested",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{},
				}
			},
			func(r *IdentityToken, t *testing.T) {
				if r.Restrictions != nil {
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{},
				}
			},
			false,
			nil,
		},
		{
			"zero existing restrictions, requested",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{},
				}
			},
			func(r *IdentityToken, t *testing.T) {
				want := &permissions.Restrictions{
					Namespace:   "/the/ns",
					Networks:    []string{"10.0.0.0/24"},
					Permissions: []string{"dog:get,put"},
				}
				if !reflect.DeepEqual(r.Restrictions, want) {
					t.Logf("want %v got %v", want, r)
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			false,
			nil,
		},
		{
			"existing restrictions, zero requested",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			func(r *IdentityToken, t *testing.T) {
				want := &permissions.Restrictions{
					Namespace:   "/the/ns",
					Networks:    []string{"10.0.0.0/24"},
					Permissions: []string{"dog:get,put"},
				}
				if !reflect.DeepEqual(r.Restrictions, want) {
					t.Logf("want %v got %v", want, r)
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{},
				}
			},
			false,
			nil,
		},
		{
			"identical",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			func(r *IdentityToken, t *testing.T) {
				want := &permissions.Restrictions{
					Namespace:   "/the/ns",
					Networks:    []string{"10.0.0.0/24"},
					Permissions: []string{"dog:get,put"},
				}
				if !reflect.DeepEqual(r.Restrictions, want) {
					t.Logf("want %v got %v", want, r)
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			false,
			nil,
		},
		{
			"requested contained in existing",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			func(r *IdentityToken, t *testing.T) {
				want := &permissions.Restrictions{
					Namespace:   "/the/ns/2",
					Networks:    []string{"10.0.0.0/32"},
					Permissions: []string{"dog:get"},
				}
				if !reflect.DeepEqual(r.Restrictions, want) {
					t.Logf("want %v got %v", want, r)
					t.Fail()
				}
			},
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the/ns/2",
						Networks:    []string{"10.0.0.0/32"},
						Permissions: []string{"dog:get"},
					},
				}
			},
			false,
			nil,
		},
		{
			"breaking namespace",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			nil,
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				want := "restriction violation: restricted namespace must be empty, '/the/ns' or one of its children"
				if err.Error() != want {
					t.Logf("want error %s, got %s", want, err)
					t.Fail()
				}
			},
		},
		{
			"breaking networks",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			nil,
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"11.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				want := "restriction violation: restricted networks must not overlap the current ones"
				if err.Error() != want {
					t.Logf("want error %s, got %s", want, err)
					t.Fail()
				}
			},
		},
		{
			"breaking permissions",
			func(*testing.T) *IdentityToken {
				return &IdentityToken{
					Restrictions: &permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put"},
					},
				}
			},
			nil,
			func(*testing.T) args {
				return args{
					permissions.Restrictions{
						Namespace:   "/the/ns",
						Networks:    []string{"10.0.0.0/24"},
						Permissions: []string{"dog:get,put,create"},
					},
				}
			},
			true,
			func(err error, t *testing.T) {
				want := "restriction violation: restricted permissions must not be more permissive than the current ones"
				if err.Error() != want {
					t.Logf("want error %s, got %s", want, err)
					t.Fail()
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			receiver := tt.init(t)
			err := receiver.Restrict(tArgs.restrictions)

			if tt.inspect != nil {
				tt.inspect(receiver, t)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("IdentityToken.Restrict error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}

func TestHashSubject(t *testing.T) {

	source := Source{Type: "oidc", Namespace: "/", Name: "corp"}

	// A relying party keys an account on the subject permanently, so the
	// scheme cannot drift without orphaning every one of them.
	if got, want := hashSubject(source, "1234"), "oc1YY0z1aA9Dffdbwvv3GihE6p68jbX63MoMMamHZR0"; got != want {
		t.Errorf("hashSubject() = %q, want %q", got, want)
	}

	// Length prefixing is what keeps a value from borrowing characters from
	// the field beside it to reach into another source's subject space.
	collisions := [][2]string{
		{"a", "b/c"},
		{"a/b", "c"},
	}
	first := hashSubject(Source{Type: "oidc", Namespace: "/", Name: collisions[0][0]}, collisions[0][1])
	second := hashSubject(Source{Type: "oidc", Namespace: "/", Name: collisions[1][0]}, collisions[1][1])
	if first == second {
		t.Errorf("%v and %v both named the subject %q", collisions[0], collisions[1], first)
	}

	// It keeps the values of a repeated claim apart from each other too, so
	// two people cannot share a subject by holding the same characters split
	// differently.
	if got, other := hashSubject(source, "a", "bc"), hashSubject(source, "ab", "c"); got == other {
		t.Errorf(`["a" "bc"] and ["ab" "c"] both named the subject %q`, got)
	}
}

func TestDeriveSubjectClaim(t *testing.T) {

	testCases := []struct {
		name       string
		source     Source
		subClaim   string
		identity   []string
		wantValues []string
	}{
		{
			name:       "oidc defaults to sub",
			source:     Source{Type: "oidc", Namespace: "/", Name: "corp"},
			identity:   []string{"sub=1234", "email=user@example.com"},
			wantValues: []string{"1234"},
		},
		{
			name:       "saml defaults to nameid",
			source:     Source{Type: "saml", Namespace: "/", Name: "adfs"},
			identity:   []string{"nameid=user@example.com"},
			wantValues: []string{"user@example.com"},
		},
		{
			name:       "a nomination wins over the default",
			source:     Source{Type: "oidc", Namespace: "/", Name: "corp"},
			subClaim:   "oid",
			identity:   []string{"sub=1234", "oid=stable-guid"},
			wantValues: []string{"stable-guid"},
		},
		{
			name:       "a type with no default takes the nomination",
			source:     Source{Type: "mtls", Namespace: "/", Name: "pki"},
			subClaim:   "serialnumber",
			identity:   []string{"commonname=some-cert", "serialnumber=42"},
			wantValues: []string{"42"},
		},
		{
			// Every value names the subject, and JWT sorts the identity as it
			// signs it, so the code grant and an exchange see them in
			// different orders and must still agree.
			name:       "a repeated claim hashes every value, in order",
			source:     Source{Type: "oidc", Namespace: "/", Name: "corp"},
			identity:   []string{"sub=zzz", "sub=aaa"},
			wantValues: []string{"aaa", "zzz"},
		},
		{
			name:     "no nomination and no default for the type",
			source:   Source{Type: "mtls", Namespace: "/", Name: "pki"},
			identity: []string{"commonname=some-cert", "serialnumber=42"},
		},
		{
			name:     "the nominated claim is absent",
			source:   Source{Type: "mtls", Namespace: "/", Name: "pki"},
			subClaim: "serialnumber",
			identity: []string{"commonname=some-cert"},
		},
		{
			name:     "the nominated claim is empty",
			source:   Source{Type: "oidc", Namespace: "/", Name: "corp"},
			identity: []string{"sub="},
		},
		{
			name:     "the identity names no source",
			source:   Source{Type: "aws"},
			identity: []string{"sub=1234"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

			idt := NewIdentityToken(testCase.source)
			idt.Identity = testCase.identity
			idt.DeriveSubjectClaim(testCase.subClaim)

			var want string
			if len(testCase.wantValues) > 0 {
				want = hashSubject(testCase.source, testCase.wantValues...)
			}

			if idt.Subject != want {
				t.Errorf("sub = %q, want %q (from %q)", idt.Subject, want, testCase.wantValues)
			}
		})
	}
}
