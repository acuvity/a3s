package auditor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"
	. "github.com/smartystreets/goconvey/convey"
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

			audit := NewAuditor(pubsub, nil)

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

			audit := NewAuditor(pubsub, []*TrackedIdentity{
				{
					Identity:   elemental.MakeIdentity("testName", "testCategory"),
					Operations: []elemental.Operation{elemental.OperationCreate},
				},
			})

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

			audit := NewAuditor(pubsub, nil)

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

		Convey("When a denied request is audited", func() {

			audit := NewAuditor(pubsub, nil)

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

			audit := NewAuditor(pubsub, []*TrackedIdentity{
				{
					Identity:   elemental.MakeIdentity("testName2", "testCategory2"),
					Operations: []elemental.Operation{elemental.OperationCreate},
				},
			})

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

			audit := NewAuditor(pubsub, []*TrackedIdentity{
				{
					Identity:   elemental.MakeIdentity("testName", "testCategory"),
					Operations: []elemental.Operation{elemental.OperationDelete},
				},
			})

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

			audit := NewAuditor(pubsub, nil)

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

			audit := NewAuditor(pubsub, nil)

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
	})
}
