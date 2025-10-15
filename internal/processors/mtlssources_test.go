package processors

import (
	"reflect"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
)

func TestInsertEntraSecrets(t *testing.T) {

	now := time.Now()

	Convey("Calling insertEntraSecret with src and orig not having entra set", t, func() {

		orig := api.NewMTLSSource()
		src := api.NewMTLSSource()

		insertEntraSecrets(src, orig)

		So(reflect.DeepEqual(src, orig), ShouldBeTrue)
	})

	Convey("Creating a new source with graph event on", t, func() {

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = true

		insertEntraSecrets(src, nil)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldNotBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(src.EntraApplicationCredentials.GraphSubscriptionIDs, ShouldBeZeroValue)
	})

	Convey("Creating a new source with graph event off", t, func() {

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = false

		insertEntraSecrets(src, nil)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(len(src.EntraApplicationCredentials.GraphSubscriptionIDs), ShouldEqual, 0)
	})

	Convey("Creating a new source with graph event nil", t, func() {

		src := api.NewMTLSSource()

		insertEntraSecrets(src, nil)

		So(src.EntraApplicationCredentials, ShouldBeNil)
	})

	Convey("Turning on graphevent when orig is off", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = false

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = true

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldNotBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(src.EntraApplicationCredentials.GraphSubscriptionIDs, ShouldBeNil)
	})

	Convey("Turning on graphevent when orig is nil", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = true

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, nil)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldNotBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(src.EntraApplicationCredentials.GraphSubscriptionIDs, ShouldBeNil)
	})

	Convey("Turning on graphevent when orig is on", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = true
		orig.EntraApplicationCredentials.GraphEventSecret = "secret"
		orig.EntraApplicationCredentials.GraphSubscriptionExpiration = now
		orig.EntraApplicationCredentials.GraphSubscriptionIDs = map[string]string{"g": "x"}

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = true

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldEqual, "secret")
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldEqual, now)
		So(src.EntraApplicationCredentials.GraphSubscriptionIDs, ShouldResemble, map[string]string{"g": "x"})
	})

	Convey("Turning off graphevent when orig is on", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = true
		orig.EntraApplicationCredentials.GraphEventSecret = "secret"
		orig.EntraApplicationCredentials.GraphSubscriptionExpiration = now
		orig.EntraApplicationCredentials.GraphSubscriptionIDs = map[string]string{"g": "x"}

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = false

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(src.EntraApplicationCredentials.GraphSubscriptionIDs, ShouldBeNil)
	})

	Convey("Turning nil graphevent when orig is on", t, func() {

		orig := api.NewMTLSSource()
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = true
		orig.EntraApplicationCredentials.GraphEventSecret = "secret"
		orig.EntraApplicationCredentials.GraphSubscriptionExpiration = now
		orig.EntraApplicationCredentials.GraphSubscriptionIDs = map[string]string{"g": "x"}

		src := api.NewMTLSSource()

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials, ShouldBeNil)
	})

	Convey("Turning off graphevent when orig is off", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = false

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = false

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(len(src.EntraApplicationCredentials.GraphSubscriptionIDs), ShouldBeZeroValue)
	})

	Convey("Turning off graphevent when orig is nil", t, func() {

		orig := api.NewMTLSSource()
		orig.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra

		src := api.NewMTLSSource()
		src.ClaimsRetrievalMode = api.MTLSSourceClaimsRetrievalModeEntra
		src.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		src.EntraApplicationCredentials.GraphEventsEnabled = false

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials.GraphEventSecret, ShouldBeEmpty)
		So(src.EntraApplicationCredentials.GraphSubscriptionExpiration, ShouldBeZeroValue)
		So(len(src.EntraApplicationCredentials.GraphSubscriptionIDs), ShouldBeZeroValue)
	})

	Convey("Turning nil graphevent when orig is off", t, func() {

		orig := api.NewMTLSSource()
		orig.EntraApplicationCredentials = api.NewMTLSSourceEntra()
		orig.EntraApplicationCredentials.GraphEventsEnabled = false

		src := api.NewMTLSSource()

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials, ShouldBeNil)
	})

	Convey("Turning nil graphevent when orig is nil", t, func() {

		orig := api.NewMTLSSource()

		src := api.NewMTLSSource()

		elemental.BackportUnexposedFields(orig, src)
		insertEntraSecrets(src, orig)

		So(src.EntraApplicationCredentials, ShouldBeNil)
	})

}
