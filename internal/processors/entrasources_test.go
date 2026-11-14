package processors

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

func TestEntraSourcesProcessor(t *testing.T) {

	Convey("Given an Entra sources processor", t, func() {

		m := maniptest.NewTestManipulator()
		p := NewEntraSourcesProcessor(m)

		bctx := bahamut.NewMockContext(context.Background())
		bctx.MockRequest = &elemental.Request{Namespace: "/ns"}

		Convey("When I create an Entra source", func() {

			var created *api.EntraSource
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				created = object.(*api.EntraSource)
				return nil
			})

			src := api.NewEntraSource()
			src.Name = "corp"
			src.TenantID = "1ec8ce6a-2b6d-4828-b298-be4d2eeb573b"
			bctx.MockInputData = src

			err := p.ProcessCreate(bctx)

			Convey("Then it should be stored in the request namespace", func() {
				So(err, ShouldBeNil)
				So(created, ShouldNotBeNil)
				So(created.Namespace, ShouldEqual, "/ns")
				So(created.CreateTime.IsZero(), ShouldBeFalse)
				So(bctx.MockOutputData, ShouldEqual, created)
			})
		})

		Convey("When I list the Entra sources", func() {

			src := api.NewEntraSource()
			src.Name = "corp"

			var namespace string
			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				namespace = mctx.Namespace()
				*dest.(*api.EntraSourcesList) = append(*dest.(*api.EntraSourcesList), src)
				return nil
			})

			err := p.ProcessRetrieveMany(bctx)

			Convey("Then I should get the sources of the request namespace", func() {
				So(err, ShouldBeNil)
				So(namespace, ShouldEqual, "/ns")
				So(*bctx.MockOutputData.(*api.EntraSourcesList), ShouldResemble, api.EntraSourcesList{src})
			})
		})
	})
}
