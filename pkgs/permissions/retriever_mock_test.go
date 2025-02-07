package permissions

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMockRetriever(t *testing.T) {

	Convey("Given a MockRetriever", t, func() {

		r := NewMockRetriever()

		Convey("Calling Permissions without mock should work", func() {
			perms, err := r.Permissions(context.Background(), []string{"a=a"}, "ns")
			So(err, ShouldBeNil)
			So(perms, ShouldNotBeNil)
			So(len(perms), ShouldEqual, 0)
		})

		Convey("Calling Permissions with mock should work", func() {
			r.MockPermissions(t, func(context.Context, []string, string, ...RetrieverOption) (PermissionMap, error) {
				return PermissionMap{"hello": {}}, nil
			})
			perms, err := r.Permissions(context.Background(), []string{"a=a"}, "ns")
			So(err, ShouldBeNil)
			So(perms, ShouldNotBeNil)
			So(len(perms), ShouldEqual, 1)
		})

		Convey("Calling Revoked without mock should work", func() {
			revoked, err := r.Revoked(context.Background(), "/", "abcdef", []string{"a"})
			So(err, ShouldBeNil)
			So(revoked, ShouldBeFalse)
		})

		Convey("Calling Revoked with mock should work", func() {
			r.MockRevoked(t, func(context.Context, string, string, []string) (bool, error) {
				return true, nil
			})
			revoked, err := r.Revoked(context.Background(), "/", "abcdef", []string{"a"})
			So(err, ShouldBeNil)
			So(revoked, ShouldBeTrue)
		})
	})
}
