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

func flattenTags(term [][]string) (set []string) {
	for _, rows := range term {
		set = append(set, rows...)
	}
	return set
}

func TestNewRetriever(t *testing.T) {
	Convey("Given have a subscriber and a manipulator", t, func() {
		m := maniptest.NewTestManipulator()
		a := NewRetriever(m).(*retriever)
		So(a.manipulator, ShouldNotBeNil)
	})
}

func TestIsAuthorizedWithToken(t *testing.T) {

	var (
		permSetAllowAll = "*:*"
		permSetOnBla    = "bla"
		ctx             = context.Background()
	)

	makeAPIPolWithSubject := func(perms []string, subnets []string, subject [][]string) *api.Authorization {
		apiauth := api.NewAuthorization()
		apiauth.ID = "1"
		apiauth.Namespace = "/a"
		apiauth.Subject = subject
		apiauth.TargetNamespaces = []string{"/a"}
		apiauth.Permissions = perms
		apiauth.Subnets = subnets
		apiauth.FlattenedSubject = flattenTags(apiauth.Subject)

		return apiauth
	}

	makeAPIPol := func(perms []string, subnets []string) *api.Authorization {
		return makeAPIPolWithSubject(perms, subnets, [][]string{{"color=blue"}})
	}

	Convey("Given I have an authorizer and a token", t, func() {

		m := maniptest.NewTestManipulator()

		r := NewRetriever(m).(*retriever)

		m.MockCount(t, func(mctx manipulate.Context, identity elemental.Identity) (int, error) {
			return 1, nil
		})

		Convey("When there is no policy matching", func() {

			perms, err := r.Permissions(ctx, []string{"color=blue", "@issuer=toto"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When I retrieving the ns fails", func() {

			m.MockCount(t, func(mctx manipulate.Context, identity elemental.Identity) (int, error) {
				return 0, fmt.Errorf("noooo")
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "noooo")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When I retrieving the ns is not found", func() {

			m.MockCount(t, func(mctx manipulate.Context, identity elemental.Identity) (int, error) {
				return 0, nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching *,*", func() {

			var expectedFilter *elemental.Filter
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
					expectedFilter = mctx.Filter()
				}
				return nil
			})

			collectedNamespaces := []string{}
			perms, err := r.Permissions(
				ctx,
				[]string{"color=blue", "@issuer=toto"},
				"/a",
				OptionCollectAccessibleNamespaces(&collectedNamespaces),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
			So(expectedFilter.String(), ShouldEqual, `flattenedsubject in ["color=blue", "@issuer=toto"] and trustedissuers contains ["toto"] and disabled == false`)
			So(collectedNamespaces, ShouldResemble, []string{"/a"})
		})

		Convey("When there is a policy matching twice using twice the same set", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:delete"}, nil),
						makeAPIPol([]string{"things:get"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is twice a perm one, says true, one says false", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, nil),
						makeAPIPol([]string{"-things:get"}, nil),
						makeAPIPol([]string{"things:get"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching with target namespace outside of restricted ns", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Namespace: "/b"}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching with target namespace equals to restricted ns", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Namespace: "/a"}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is a policy matching with target namespace a child of restricted ns", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a/b",
				OptionRetrieverRestrictions(Restrictions{Namespace: "/a"}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is a policy matching with target namespace a parent of restricted ns", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Namespace: "/a/b"}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching with a bad targetNs", func() {

			pol := makeAPIPol([]string{permSetAllowAll}, nil)
			pol.TargetNamespaces = []string{"/az/b/c"}

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						pol,
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy that is not matching", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"nope,*"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching a group", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPolWithSubject([]string{"things:get"}, nil, [][]string{{"@group:name=people"}}),
					)
				}
				if dest.Identity().IsEqual(api.GroupIdentity) {
					*dest.(*api.GroupsList) = append(
						*dest.(*api.GroupsList),
						&api.Group{
							Name:             "people",
							Subject:          [][]string{{"color=blue"}},
							FlattenedSubject: []string{"color=blue"},
							Weight:           10,
						},
						&api.Group{
							Name:             "animals",
							Subject:          [][]string{{"color=blue"}},
							FlattenedSubject: []string{"color=blue"},
							Weight:           5,
						},
						&api.Group{
							Name:             "aliens",
							Subject:          [][]string{{"color=red"}},
							FlattenedSubject: []string{"color=red"},
							Weight:           5,
						},
					)
				}
				return nil
			})

			collectedGroups := []string{}
			perms, err := r.Permissions(
				ctx,
				[]string{"color=blue"},
				"/a",
				OptionCollectGroups(&collectedGroups),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
			So(len(collectedGroups), ShouldEqual, 2)
			So(collectedGroups, ShouldContain, "people")
			So(collectedGroups, ShouldContain, "animals")
		})

		Convey("When there is a policy matching a group in single mode", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPolWithSubject([]string{"things:get"}, nil, [][]string{{"@group:name=animals"}}),
					)
				}
				if dest.Identity().IsEqual(api.GroupIdentity) {
					*dest.(*api.GroupsList) = append(
						*dest.(*api.GroupsList),
						&api.Group{
							Name:             "people",
							Subject:          [][]string{{"color=blue"}},
							FlattenedSubject: []string{"color=blue"},
							Weight:           10,
						},
						&api.Group{
							Name:             "animals",
							Subject:          [][]string{{"color=blue"}},
							FlattenedSubject: []string{"color=blue"},
							Weight:           15,
						},
						&api.Group{
							Name:             "aliens",
							Subject:          [][]string{{"color=red"}},
							FlattenedSubject: []string{"color=red"},
							Weight:           5,
						},
					)
				}
				return nil
			})

			collectedGroups := []string{}
			perms, err := r.Permissions(
				ctx,
				[]string{"color=blue"},
				"/a",
				OptionSingleGroupMode(true),
				OptionCollectGroups(&collectedGroups),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
			So(len(collectedGroups), ShouldEqual, 1)
			So(collectedGroups, ShouldContain, "animals")
		})

		Convey("When there is a policy matching but not on the correct permission set", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetOnBla}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is a policy with matching restriction", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, []string{"10.0.0.0/8", "11.0.0.0/8"}),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverSourceIP("11.2.2.2"),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is a policy with not matching restriction", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, []string{"10.0.0.0/8", "11.0.0.0/8"}),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverSourceIP("13.2.2.2"),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy invalid IP", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, []string{"10.0.0.0/8", "11.0.0.0/8"}),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverSourceIP(".2.2.2"),
			)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "missing or invalid origin IP '.2.2.2'")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy invalid declared CIDR", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, []string{"dawf"}),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverSourceIP("2.2.2.2"),
			)

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "invalid CIDR address: dawf")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy with empty subject", func() {

			pol := makeAPIPol([]string{}, nil)
			pol.Subject = [][]string{{}}

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						pol,
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy with empty string subject", func() {

			pol := makeAPIPol([]string{}, nil)
			pol.Subject = [][]string{{""}}

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						pol,
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy with nil subject", func() {

			pol := makeAPIPol([]string{}, nil)
			pol.Subject = [][]string{nil}

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						pol,
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When retrieving the policy fails", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					return fmt.Errorf("boom")
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to resolve authorizations: boom")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When retrieving the groups fails", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.GroupIdentity) {
					return fmt.Errorf("boom")
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to resolve groups: boom")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When retrieving the policy with an invalid allowedSubnet", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{}, []string{".2.2.2."}),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "missing or invalid origin IP ''")
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		// Restrictions

		Convey("When there is a policy matching but the namespace is restricted", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"@auth:role=testrole2"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Namespace: "/b"}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching but the permissions are restricted", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Permissions: []string{"dog,get"}}),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy matching but the permissions are restricted AND offloaded", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverRestrictions(Restrictions{Permissions: []string{"dog,get"}}),
				OptionOffloadPermissionsRestrictions(true),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		Convey("When there is a policy matching but the networks are restricted", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{permSetAllowAll}, nil),
					)
				}
				return nil
			})

			Convey("When I the networks are correct", func() {

				perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
					OptionRetrieverSourceIP("127.0.0.1"),
					OptionRetrieverRestrictions(Restrictions{Networks: []string{"10.0.0.0/8"}}),
				)

				So(err, ShouldBeNil)
				So(perms.Allows("get", "things"), ShouldEqual, false)
			})

			Convey("When I the networks are incorrect", func() {

				perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
					OptionRetrieverSourceIP("1.1.1.1"),
					OptionRetrieverRestrictions(Restrictions{Networks: []string{"how-come?"}}),
				)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, `invalid CIDR address: how-come?`)
				So(perms.Allows("get", "things"), ShouldEqual, false)
			})
		})

		// Single ID target

		Convey("When there is a policy with id restriction and not id provided", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get:xyz,abc"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy with id restriction and not matching id provided", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get:xyz,abc"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverID("nope-id"),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, false)
		})

		Convey("When there is a policy with id restriction and matching id provided", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get:xyz,abc"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a",
				OptionRetrieverID("xyz"),
			)

			So(err, ShouldBeNil)
			So(perms.Allows("get", "things"), ShouldEqual, true)
		})

		// Label
		Convey("When there there is no label option", func() {

			var expectedPolFilter *elemental.Filter
			var expectedGroupFilter *elemental.Filter
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					expectedPolFilter = mctx.Filter()
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, nil),
					)
				}
				if dest.Identity().IsEqual(api.GroupIdentity) {
					expectedGroupFilter = mctx.Filter()
				}
				return nil
			})

			_, err := r.Permissions(ctx, []string{"color=blue"}, "/a")
			So(err, ShouldBeNil)
			So(expectedPolFilter.String(), ShouldEqual, `flattenedsubject in ["color=blue"] and trustedissuers contains [""] and disabled == false`)
			So(expectedGroupFilter.String(), ShouldEqual, `flattenedsubject in ["color=blue"] and disabled == false`)
		})

		Convey("When there there is a label option", func() {

			var expectedPolFilter *elemental.Filter
			var expectedGroupFilter *elemental.Filter
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					expectedPolFilter = mctx.Filter()
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"things:get"}, nil),
					)
				}
				if dest.Identity().IsEqual(api.GroupIdentity) {
					expectedGroupFilter = mctx.Filter()
				}
				return nil
			})

			_, err := r.Permissions(ctx, []string{"color=blue"}, "/a", OptionFilterLabel("the-label"))
			So(err, ShouldBeNil)
			So(expectedPolFilter.String(), ShouldEqual, `flattenedsubject in ["color=blue"] and trustedissuers contains [""] and disabled == false and label == "the-label"`)
			So(expectedGroupFilter.String(), ShouldEqual, `flattenedsubject in ["color=blue"] and disabled == false and label == "the-label"`)
		})
	})
}

func TestPermissionsWithToken(t *testing.T) {

	var (
		testrole1 = "stuff:*"
		testrole2 = "*:*"
		testrole3 = "bla:get,post,put"
		ctx       = context.Background()
	)

	makeAPIPol := func(perms []string, subnets []string) *api.Authorization {
		apiauth := api.NewAuthorization()
		apiauth.ID = "1"
		apiauth.Namespace = "/a"
		apiauth.Subject = [][]string{{"color=blue"}}
		apiauth.TargetNamespaces = []string{"/"}
		apiauth.Permissions = perms
		apiauth.Subnets = subnets
		apiauth.FlattenedSubject = flattenTags(apiauth.Subject)

		return apiauth
	}

	Convey("Given I have an authorizer and a token", t, func() {

		m := maniptest.NewTestManipulator()

		r := NewRetriever(m).(*retriever)

		m.MockCount(t, func(mctx manipulate.Context, identity elemental.Identity) (int, error) {
			return 1, nil
		})

		Convey("When I call Authorizations when I have no policy", func() {

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{})
		})

		Convey("When I call Authorizations when I have the role testroles2", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{testrole2}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{
				"*": {"*": true},
			})
		})

		Convey("When I call Authorizations when I have the role testroles1 and testrole3", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{testrole1, testrole3}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{
				"bla":   {"get": true, "post": true, "put": true},
				"stuff": {"*": true},
			})
		})

		Convey("When I call Authorizations when I have with individual authotization", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				if dest.Identity().IsEqual(api.AuthorizationIdentity) {
					*dest.(*api.AuthorizationsList) = append(
						*dest.(*api.AuthorizationsList),
						makeAPIPol([]string{"r1:get,post", "r2:put"}, nil),
					)
				}
				return nil
			})

			perms, err := r.Permissions(ctx, []string{"color=blue"}, "/a")

			So(err, ShouldBeNil)
			So(perms, ShouldResemble, PermissionMap{
				"r1": {"get": true, "post": true},
				"r2": {"put": true},
			})
		})
	})
}

func TestCountNamespace(t *testing.T) {

	Convey("Given I have a http manipulator and an authorizer", t, func() {

		m := maniptest.NewTestManipulator()

		r := NewRetriever(m).(*retriever)

		Convey("When I call countNamespace", func() {

			attempt := -1
			consistency := manipulate.ReadConsistencyDefault
			m.MockCount(t, func(mctx manipulate.Context, identity elemental.Identity) (int, error) {
				consistency = mctx.ReadConsistency()
				attempt++
				return attempt, nil
			})

			count, err := r.countNamespace(context.Background(), "ns")

			So(err, ShouldBeNil)
			So(count, ShouldEqual, 1)
			So(consistency, ShouldEqual, manipulate.ReadConsistencyStrong)
		})
	})
}
