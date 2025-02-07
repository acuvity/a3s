package permissions

import (
	"context"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

func TestNewRemoteRetriever(t *testing.T) {
	Convey("Calling NewRemoteRetriever should work", t, func() {
		m := maniptest.NewTestManipulator()
		r := NewRemoteRetriever(m)
		So(r.(*remoteRetriever).manipulator, ShouldEqual, m)
		So(r.(*remoteRetriever).transformer, ShouldEqual, nil)
	})
}

func TestNewRemoteRetrieverWithTransformer(t *testing.T) {
	Convey("Calling NewRemoteRetrieverWithTransformer should work", t, func() {
		m := maniptest.NewTestManipulator()
		mockTransformer := NewMockTransformer()
		r := NewRemoteRetrieverWithTransformer(m, mockTransformer)
		So(r.(*remoteRetriever).manipulator, ShouldEqual, m)
		So(r.(*remoteRetriever).transformer, ShouldEqual, mockTransformer)
	})
}

func TestPermissions(t *testing.T) {

	Convey("Given a remote permissions retriever", t, func() {

		m := maniptest.NewTestManipulator()
		r := NewRemoteRetriever(m)

		Convey("When retrieving subscriptions is OK", func() {

			var expectedClaims []string
			var expectedNamespace string
			var expectedRestrictions Restrictions
			var expectedOffloadPermissionsRestrictions bool
			var expectedID string
			var expectedIP string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				o := object.(*api.Permissions)
				o.Permissions = map[string]map[string]bool{
					"cat": {"pet": false},
					"dog": {"pet": true},
				}
				o.CollectedAccessibleNamespaces = []string{"/a/b", "/a/x"}
				o.CollectedGroups = []string{"g1", "g2"}
				expectedClaims = o.Claims
				expectedNamespace = o.Namespace
				expectedID = o.ID
				expectedIP = o.IP
				expectedOffloadPermissionsRestrictions = o.OffloadPermissionsRestrictions
				expectedRestrictions = Restrictions{
					Namespace:   o.RestrictedNamespace,
					Permissions: o.RestrictedPermissions,
					Networks:    o.RestrictedNetworks,
				}

				return nil
			})

			collectedNamespaces := []string{}
			collectedGroups := []string{}
			perms, err := r.Permissions(
				context.Background(),
				[]string{"a=a"},
				"/the/ns",
				OptionCollectAccessibleNamespaces(&collectedNamespaces),
				OptionCollectGroups(&collectedGroups),
				OptionRetrieverID("id"),
				OptionRetrieverSourceIP("1.1.1.1"),
				OptionRetrieverRestrictions(Restrictions{
					Namespace:   "/the/ns/sub",
					Networks:    []string{"1.1.1.1/32", "2.2.2.2/32"},
					Permissions: []string{"cat:pet"},
				}),
			)

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{
				"cat": Permissions{"pet": false},
				"dog": Permissions{"pet": true},
			})
			So(expectedClaims, ShouldResemble, []string{"a=a"})
			So(expectedNamespace, ShouldResemble, "/the/ns")
			So(expectedID, ShouldEqual, "id")
			So(expectedIP, ShouldEqual, "1.1.1.1")
			So(expectedOffloadPermissionsRestrictions, ShouldBeFalse)
			So(expectedRestrictions, ShouldResemble, Restrictions{
				Namespace:   "/the/ns/sub",
				Networks:    []string{"1.1.1.1/32", "2.2.2.2/32"},
				Permissions: []string{"cat:pet"},
			})
			So(collectedNamespaces, ShouldResemble, []string{"/a/b", "/a/x"})
			So(collectedGroups, ShouldResemble, []string{"g1", "g2"})
		})

		Convey("When retrieving permissions fails", func() {

			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return fmt.Errorf("boom")
			})

			_, err := r.Permissions(
				context.Background(),
				[]string{"a=a"},
				"/the/ns",
				OptionRetrieverID("id"),
			)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "boom")
		})

		Convey("When retrieving subscriptions with a defined transformer", func() {

			mockTransformer := NewMockTransformer()
			mockTransformer.MockTransform(t, func(permissions PermissionMap) PermissionMap {
				for k := range permissions {
					if k == "petter" {
						permissions["dog"] = Permissions{"pet": true}
						permissions["cat"] = Permissions{"pet": true}
						delete(permissions, k)
					}
				}
				return permissions
			})

			r = NewRemoteRetrieverWithTransformer(m, mockTransformer)

			var expectedClaims []string
			var expectedNamespace string
			var expectedRestrictions Restrictions
			var expectedOffloadPermissionsRestrictions bool
			var expectedID string
			var expectedIP string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				o := object.(*api.Permissions)
				o.Permissions = map[string]map[string]bool{
					"petter": {},
				}
				expectedClaims = o.Claims
				expectedNamespace = o.Namespace
				expectedID = o.ID
				expectedIP = o.IP
				expectedOffloadPermissionsRestrictions = o.OffloadPermissionsRestrictions
				expectedRestrictions = Restrictions{
					Namespace:   o.RestrictedNamespace,
					Permissions: o.RestrictedPermissions,
					Networks:    o.RestrictedNetworks,
				}

				return nil
			})

			perms, err := r.Permissions(
				context.Background(),
				[]string{"a=a"},
				"/the/ns",
				OptionRetrieverID("id"),
				OptionRetrieverSourceIP("1.1.1.1"),
				OptionRetrieverRestrictions(Restrictions{
					Namespace:   "/the/ns/sub",
					Networks:    []string{"1.1.1.1/32", "2.2.2.2/32"},
					Permissions: []string{"cat:pet"},
				}),
			)

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{
				"cat": Permissions{
					"pet": true,
				},
			})
			So(expectedClaims, ShouldResemble, []string{"a=a"})
			So(expectedNamespace, ShouldResemble, "/the/ns")
			So(expectedID, ShouldEqual, "id")
			So(expectedIP, ShouldEqual, "1.1.1.1")
			So(expectedOffloadPermissionsRestrictions, ShouldBeTrue)
			So(expectedRestrictions, ShouldResemble, Restrictions{
				Namespace:   "/the/ns/sub",
				Networks:    []string{"1.1.1.1/32", "2.2.2.2/32"},
				Permissions: []string{"cat:pet"},
			})
		})
	})
}

func TestRevoked(t *testing.T) {

	Convey("Given a remote permissions retriever", t, func() {

		m := maniptest.NewTestManipulator()
		r := NewRemoteRetriever(m)

		Convey("When retrieving revocations is OK and not revoked", func() {

			var expectedIdentity elemental.Identity
			var expectedFilter *elemental.Filter
			var expectedNamespace string
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				expectedIdentity = dest.Identity()
				expectedFilter = mctx.Filter()
				expectedNamespace = mctx.Namespace()

				*dest.(*api.SparseRevocationsList) = append(
					*dest.(*api.SparseRevocationsList),
					&api.SparseRevocation{
						TokenID: func() *string { s := "not-abcdef"; return &s }(),
						Subject: func() *[][]string { s := [][]string{{"b=b"}}; return &s }(),
					},
				)
				return nil
			})

			revoked, err := r.Revoked(context.Background(), "/ns", "abcdef", []string{"a"})

			So(err, ShouldBeNil)
			So(expectedIdentity.IsEqual(api.RevocationIdentity), ShouldBeTrue)
			So(expectedNamespace, ShouldEqual, "/ns")
			So(expectedFilter.String(), ShouldEqual, `((tokenID == "abcdef") or (flattenedsubject in ["a"]))`)
			So(revoked, ShouldBeFalse)
		})

		Convey("When retrieving revocations is OK and is revoked by token ID", func() {

			var expectedIdentity elemental.Identity
			var expectedFilter *elemental.Filter
			var expectedNamespace string
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				expectedIdentity = dest.Identity()
				expectedFilter = mctx.Filter()
				expectedNamespace = mctx.Namespace()

				*dest.(*api.SparseRevocationsList) = append(
					*dest.(*api.SparseRevocationsList),
					&api.SparseRevocation{
						TokenID: func() *string { s := "abcdef"; return &s }(),
						Subject: func() *[][]string { s := [][]string{{"b=b"}}; return &s }(),
					},
				)
				return nil
			})

			revoked, err := r.Revoked(context.Background(), "/ns", "abcdef", []string{"a"})

			So(err, ShouldBeNil)
			So(expectedIdentity.IsEqual(api.RevocationIdentity), ShouldBeTrue)
			So(expectedNamespace, ShouldEqual, "/ns")
			So(expectedFilter.String(), ShouldEqual, `((tokenID == "abcdef") or (flattenedsubject in ["a"]))`)
			So(revoked, ShouldBeTrue)
		})

		Convey("When retrieving revocations is OK and is revoked by subject", func() {

			var expectedIdentity elemental.Identity
			var expectedFilter *elemental.Filter
			var expectedNamespace string
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				expectedIdentity = dest.Identity()
				expectedFilter = mctx.Filter()
				expectedNamespace = mctx.Namespace()

				*dest.(*api.SparseRevocationsList) = append(
					*dest.(*api.SparseRevocationsList),
					&api.SparseRevocation{
						TokenID: func() *string { s := "not-abcdef"; return &s }(),
						Subject: func() *[][]string { s := [][]string{{"a"}}; return &s }(),
					},
				)
				return nil
			})

			revoked, err := r.Revoked(context.Background(), "/ns", "abcdef", []string{"a"})

			So(err, ShouldBeNil)
			So(expectedIdentity.IsEqual(api.RevocationIdentity), ShouldBeTrue)
			So(expectedNamespace, ShouldEqual, "/ns")
			So(expectedFilter.String(), ShouldEqual, `((tokenID == "abcdef") or (flattenedsubject in ["a"]))`)
			So(revoked, ShouldBeTrue)
		})

		Convey("When retrieving revocations is not OK", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				return fmt.Errorf("boom")
			})

			revoked, err := r.Revoked(context.Background(), "/", "abcdef", []string{"a"})

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to retrieve revocations: boom")
			So(revoked, ShouldBeFalse)
		})
	})
}
