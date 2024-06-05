package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/andreyvit/diff"
	"github.com/mitchellh/mapstructure"
	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

func TestAudit(t *testing.T) {

	Convey("Given I have a pubsub client", t, func() {

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		pubsub := bahamut.NewLocalPubSubClient()
		_ = pubsub.Connect(ctx)

		recvmsg := make(chan *notification.Message, 2)
		h := func(msg *notification.Message) {
			recvmsg <- msg
		}

		Convey("When an allowed request is audited, all identities", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
			})
		})

		Convey("When an allowed request is audited, tracked identity", func() {

			audit := NewAuditor(api.Manager(), pubsub, OptionTrackedIdentities(&TrackedIdentity{
				Identity:   elemental.MakeIdentity("testName", "testCategory"),
				Operations: []elemental.Operation{elemental.OperationCreate},
			}))

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
			})
		})

		Convey("When a request is audited with metadata claims", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetMetadata(MetadataKeyAudit, []string{"something=else", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
			})
		})

		Convey("When an allowed update request with a diff is audited", func() {

			audit := NewAuditor(api.Manager(), pubsub, OptionIgnoredAttributes(
				"createTime",
				"updateTime",
			))

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			original := api.NewNamespace()
			original.ID = "1234"
			original.Name = "/something/testName"
			original.Description = "testDescription"
			original.Label = "something"
			original.Namespace = "/something"
			original.Opaque = map[string]any{
				"something": "else",
				"another":   []string{"item"},
			}

			updated := original.DeepCopy()
			updated.Description = "updatedDescription"
			updated.Label = ""
			updated.Opaque = map[string]any{
				"something": "different",
				"another":   []string{"item", "extra"},
				"new":       1,
			}

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationUpdate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: original.Namespace,
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})
			bctx.SetOriginalData(original)
			bctx.SetOutputData(updated)

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationUpdate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationUpdate,
				ID:        "1234",
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Name:      "/something/testName",
				Namespace: "/something",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
				Diff: createDiff(original, updated),
			})
		})

		Convey("When an allowed update request with no diff is audited", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			original := api.NewNamespace()
			original.ID = "1234"
			original.Name = "/something/testName"
			original.Description = "testDescription"
			original.Namespace = "/something"
			original.Opaque = map[string]any{
				"something": "else",
				"another":   []string{"item"},
			}

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationUpdate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: original.Namespace,
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})
			bctx.SetOriginalData(original)
			bctx.SetOutputData(original)

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationUpdate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationUpdate,
				ID:        "1234",
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Name:      "/something/testName",
				Namespace: "/something",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
				Diff: "",
			})
		})

		Convey("When an allowed update request with no original data is audited", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			original := api.NewNamespace()
			original.ID = "1234"
			original.Name = "/something/testName"
			original.Description = "testDescription"
			original.Namespace = "/something"
			original.Opaque = map[string]any{
				"something": "else",
				"another":   []string{"item"},
			}

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationUpdate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: original.Namespace,
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})
			bctx.SetOutputData(original)

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationUpdate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationUpdate,
				ID:        "1234",
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Name:      "/something/testName",
				Namespace: "/something",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
				Diff: "",
			})
		})

		Convey("When a denied request is audited", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})

			err := fmt.Errorf("boom")

			audit.Audit(bctx, err)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{
					"something": "else",
					"a":         "token",
				},
				Error: err.Error(),
			})
		})

		Convey("When a request identity is ignored", func() {

			audit := NewAuditor(api.Manager(), pubsub, OptionTrackedIdentities(&TrackedIdentity{
				Identity:   elemental.MakeIdentity("testName2", "testCategory2"),
				Operations: []elemental.Operation{elemental.OperationCreate},
			}))

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
			}

			So(msg, ShouldBeNil)
		})

		Convey("When a request operation is ignored", func() {

			audit := NewAuditor(api.Manager(), pubsub, OptionTrackedIdentities(&TrackedIdentity{
				Identity:   elemental.MakeIdentity("testName", "testCategory"),
				Operations: []elemental.Operation{elemental.OperationDelete},
			}))

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
			}

			So(msg, ShouldBeNil)
		})

		Convey("When a request is audited with malformed metadata claims", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetMetadata(MetadataKeyAudit, []string{"somethingelse", "somethingelse=", "a=token"})

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{
					"a": "token",
				},
			})
		})

		Convey("When a request is audited with unsupported metadata claims", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationCreate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetMetadata(MetadataKeyAudit, "something=else")

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
				panic("test did not get response in time")
			}

			So(msg, ShouldNotBeNil)
			So(msg.Type, ShouldEqual, string(elemental.OperationCreate))

			var sentMsg *AuditMessage
			So(mapstructure.Decode(msg.Data, &sentMsg), ShouldBeNil)

			So(sentMsg, ShouldResemble, &AuditMessage{
				Operation: elemental.OperationCreate,
				Identity:  elemental.MakeIdentity("testName", "testCategory"),
				Namespace: "testNamespace",
				ClaimsMap: map[string]string{},
			})
		})

		Convey("When an allowed update request with a diff has malformed output data", func() {

			audit := NewAuditor(api.Manager(), pubsub)

			notification.Subscribe(ctx, pubsub, NotificationAudit, h)

			bctx := bahamut.NewContext(ctx,
				&elemental.Request{
					Operation: elemental.OperationUpdate,
					Identity:  elemental.MakeIdentity("testName", "testCategory"),
					Namespace: "testNamespace",
				},
			)
			bctx.SetClaims([]string{"something=else", "a=token"})
			bctx.SetOutputData("something")

			audit.Audit(bctx, nil)

			var msg *notification.Message
			select {
			case msg = <-recvmsg:
			case <-time.After(300 * time.Millisecond):
			}

			So(msg, ShouldBeNil)
		})
	})
}

func createDiff(orig, updated any) string {
	var origData, updatedData map[string]any

	err := mapstructure.Decode(orig, &origData)
	So(err, ShouldBeNil)

	err = mapstructure.Decode(updated, &updatedData)
	So(err, ShouldBeNil)

	for key, origVal := range origData {
		outVal, ok := updatedData[key]
		if !ok {
			continue
		}

		if reflect.DeepEqual(origVal, outVal) {
			delete(origData, key)
			delete(updatedData, key)
		}
	}

	jsonOrig, err := json.MarshalIndent(origData, "", "  ")
	So(err, ShouldBeNil)

	jsonOutput, err := json.MarshalIndent(updatedData, "", "  ")
	So(err, ShouldBeNil)

	return diff.LineDiff(string(jsonOrig), string(jsonOutput))
}
