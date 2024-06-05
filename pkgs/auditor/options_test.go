package auditor

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/elemental"
)

func TestOption(t *testing.T) {

	Convey("OptionTrackedIdentities should work", t, func() {
		cfg := &config{}
		OptionTrackedIdentities(
			&TrackedIdentity{
				Identity:   elemental.MakeIdentity("testName", "testCategory"),
				Operations: []elemental.Operation{elemental.OperationDelete},
			},
			&TrackedIdentity{
				Identity:   elemental.MakeIdentity("testName2", "testCategory2"),
				Operations: []elemental.Operation{elemental.OperationCreate},
			},
		)(cfg)
		So(cfg.trackedIdentities, ShouldResemble, []*TrackedIdentity{
			{
				Identity:   elemental.MakeIdentity("testName", "testCategory"),
				Operations: []elemental.Operation{elemental.OperationDelete},
			},
			{
				Identity:   elemental.MakeIdentity("testName2", "testCategory2"),
				Operations: []elemental.Operation{elemental.OperationCreate},
			},
		})
	})

	Convey("OptionIgnoredAttributes should work", t, func() {
		cfg := &config{}
		OptionIgnoredAttributes("r1", "r2")(cfg)
		So(cfg.ignoredAttributes, ShouldResemble, []string{"r1", "r2"})
	})
}
