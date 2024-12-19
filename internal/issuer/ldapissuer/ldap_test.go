package ldapissuer

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"
	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
)

func TestErrLDAP(t *testing.T) {
	Convey("ErrLDAP should work", t, func() {
		e := fmt.Errorf("boom")
		err := ErrLDAP{Err: e}
		So(err.Error(), ShouldEqual, "ldap error: boom")
		So(err.Unwrap(), ShouldEqual, e)
	})
}

func TestNewLDAPIssuer(t *testing.T) {
	Convey("Calling NewLDAPIssuer should work", t, func() {
		src := api.NewLDAPSource()
		src.Namespace = "/my/ns"
		src.Name = "my-src"
		iss := newLDAPIssuer(src)
		So(iss.source, ShouldEqual, src)
		So(iss.token.Source.Type, ShouldEqual, "ldap")
		So(iss.token.Source.Namespace, ShouldEqual, "/my/ns")
		So(iss.token.Source.Name, ShouldEqual, "my-src")
		So(iss.Issue(), ShouldEqual, iss.token)
	})
}

func TestFromCredential(t *testing.T) {

	Convey("Given a LDAP Issuer and a source with no address", t, func() {
		src := api.NewLDAPSource()
		src.Namespace = "/my/ns"
		src.Name = "my-src"
		src.SecurityProtocol = api.LDAPSourceSecurityProtocolInbandTLS
		iss := newLDAPIssuer(src)
		err := iss.fromCredentials(context.Background(), "", "")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `ldap error: cannot dial: LDAP Result Code 200 "Network Error": dial tcp: missing address`)
	})

	Convey("Given a LDAP Issuer and a source with a ca", t, func() {
		src := api.NewLDAPSource()
		src.Namespace = "/my/ns"
		src.Name = "my-src"
		src.CA = "a-ca"
		src.SecurityProtocol = api.LDAPSourceSecurityProtocolInbandTLS
		iss := newLDAPIssuer(src)
		err := iss.fromCredentials(context.Background(), "", "")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `ldap error: cannot dial: LDAP Result Code 200 "Network Error": dial tcp: missing address`)
	})

	Convey("Given a LDAP Issuer and a source using TLS", t, func() {
		src := api.NewLDAPSource()
		src.Namespace = "/my/ns"
		src.Name = "my-src"
		src.SecurityProtocol = api.LDAPSourceSecurityProtocolTLS
		iss := newLDAPIssuer(src)
		err := iss.fromCredentials(context.Background(), "", "")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, `ldap error: cannot dial tls: LDAP Result Code 200 "Network Error": dial tcp: missing address`)
	})
}

func Test_computeLDAPClaims(t *testing.T) {
	type args struct {
		entry *ldap.Entry
		dn    *ldap.DN
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 []string
	}{
		{
			"standard test",
			func(*testing.T) args {
				return args{
					&ldap.Entry{
						DN: "hello",
						Attributes: []*ldap.EntryAttribute{
							{Name: "userPassword", Values: []string{"skipped"}},
							{Name: "objectClass", Values: []string{"skipped"}},
							{Name: "comment", Values: []string{"skipped"}},
							{Name: "key1", Values: []string{"value1-1", "value1-2", ""}},
							{Name: "@@key2", Values: []string{"value1-1", ""}},
							{Name: "novalues", Values: nil},
						},
					},
					&ldap.DN{
						RDNs: []*ldap.RelativeDN{
							{
								Attributes: []*ldap.AttributeTypeAndValue{
									{Type: "ou", Value: "the-ou"},
								},
							},
							{
								Attributes: []*ldap.AttributeTypeAndValue{
									{Type: "dc", Value: "the-dc"},
								},
							},
						},
					},
				}
			},
			[]string{"dn=hello", "ou=the-ou", "dc=the-dc", "key1=value1-1", "key1=value1-2", "key2=value1-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := computeLDAPClaims(tArgs.entry, tArgs.dn)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("computeClaims got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
