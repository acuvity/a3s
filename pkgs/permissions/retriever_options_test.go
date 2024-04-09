package permissions

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRetrieverOptions(t *testing.T) {

	Convey("OptionRetrievedID should work", t, func() {
		cfg := &config{}
		OptionRetrieverID("xxx")(cfg)
		So(cfg.id, ShouldEqual, "xxx")
	})

	Convey("OptionRetrievedSourceIP should work", t, func() {
		cfg := &config{}
		OptionRetrieverSourceIP("1.2.3.4")(cfg)
		So(cfg.addr, ShouldEqual, "1.2.3.4")
	})

	Convey("Option should work", t, func() {
		cfg := &config{}
		r := Restrictions{Namespace: "/a"}
		OptionRetrieverRestrictions(r)(cfg)
		So(cfg.restrictions, ShouldResemble, r)
	})

	Convey("OptionOffloadPermissionsRestrictions should work", t, func() {
		cfg := &config{}
		OptionOffloadPermissionsRestrictions(true)(cfg)
		So(cfg.offloadPermissionsRestrictions, ShouldBeTrue)
	})

	Convey("OptionPopulateAccessibleNamespaces should work", t, func() {
		cfg := &config{}
		out := &[]string{}
		OptionCollectAccessibleNamespaces(out)(cfg)
		So(cfg.accessibleNamespaces, ShouldEqual, out)
	})

	Convey("OptionFilerLabel should work", t, func() {
		cfg := &config{}
		OptionFilterLabel("label")(cfg)
		So(cfg.label, ShouldEqual, "label")
	})

	Convey("OptionCollectGroups should work", t, func() {
		cfg := &config{}
		out := &[]string{}
		OptionCollectGroups(out)(cfg)
		So(cfg.collectedGroups, ShouldEqual, out)
	})

	Convey("OptionSingleGroupMode should work", t, func() {
		cfg := &config{}
		OptionSingleGroupMode(true)(cfg)
		So(cfg.singleGroupMode, ShouldBeTrue)
	})
}
