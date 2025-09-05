package authorizer

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
)

func TestOption(t *testing.T) {

	Convey("OptionIgnoredResources should work", t, func() {
		cfg := &config{}
		OptionIgnoredResources("r1", "r2")(cfg)
		So(cfg.ignoredResources, ShouldResemble, []string{"r1", "r2"})
	})

	Convey("OptionOperationTransformer should work", t, func() {
		cfg := &config{}
		t := NewMockOperationTransformer()
		OptionOperationTransformer(t)(cfg)
		So(cfg.operationTransformer, ShouldResemble, t)
	})

	Convey("OptionDefaultFilterLabel should work", t, func() {
		cfg := &config{}
		OptionDefaultFilterLabel("label")(cfg)
		So(cfg.defaultLabel, ShouldEqual, "label")
	})
}

func TestOptionCheck(t *testing.T) {

	Convey("OptionCheckSourceIP should work", t, func() {
		cfg := &checkConfig{}
		OptionCheckSourceIP("1.1.1.1")(cfg)
		So(cfg.sourceIP, ShouldEqual, "1.1.1.1")
	})

	Convey("OptionCheckID should work", t, func() {
		cfg := &checkConfig{}
		OptionCheckID("id")(cfg)
		So(cfg.id, ShouldEqual, "id")
	})

	Convey("OptionCheckRestrictions should work", t, func() {
		cfg := &checkConfig{}
		r := permissions.Restrictions{Namespace: "/a"}
		OptionCheckRestrictions(r)(cfg)
		So(cfg.restrictions, ShouldResemble, r)
	})

	Convey("OptionCheckToken should work", t, func() {
		cfg := &checkConfig{}
		t := &token.IdentityToken{}
		OptionCheckToken(t)(cfg)
		So(cfg.token, ShouldEqual, t)
	})

	Convey("OptionCollectAccessibleNamespaces should work", t, func() {
		cfg := &checkConfig{}
		ns := &[]string{}
		OptionCollectAccessibleNamespaces(ns)(cfg)
		So(cfg.accessibleNamespaces, ShouldEqual, ns)
	})

	Convey("OptionFilterLabel should work", t, func() {
		cfg := &checkConfig{}
		OptionFilterLabel("label")(cfg)
		So(cfg.label, ShouldEqual, "label")
	})

	Convey("OptionCollectGroups should work", t, func() {
		cfg := &checkConfig{}
		groups := &[]string{}
		OptionCollectGroups(groups)(cfg)
		So(cfg.collectedGroups, ShouldEqual, groups)
	})

	Convey("OptionSingleGroupMode should work", t, func() {
		cfg := &checkConfig{}
		OptionSingleGroupMode(true)(cfg)
		So(cfg.singleGroupMode, ShouldBeTrue)
	})
}
