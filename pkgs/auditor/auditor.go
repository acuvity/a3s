package auditor

import (
	"log/slog"
	"slices"

	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// Constants for notification topics.
const (
	NotificationAudit = "notifications.audit"
)

// AuditMessage outlines what an audit notification will contain.
type AuditMessage struct {
	Operation elemental.Operation
	Identity  elemental.Identity
	Namespace string
	ClaimsMap map[string]string
	Error     string
}

// Auditor outlines what an auditor contains.
type Auditor struct {
	pubsub            bahamut.PubSubClient
	trackedIdentities map[elemental.Identity]*TrackedIdentity

	bahamut.Auditer
}

// TrackedIdentity contains the indetity we want to track across the specified
// operations. If operations are empty it will track all actions.
type TrackedIdentity struct {
	Identity   elemental.Identity
	Operations []elemental.Operation
}

// NewAuditor returns a new Auditor.
func NewAuditor(pubsub bahamut.PubSubClient, identities []*TrackedIdentity) *Auditor {

	trackedIdentities := map[elemental.Identity]*TrackedIdentity{}

	for _, trackedIdentity := range identities {
		trackedIdentities[trackedIdentity.Identity] = trackedIdentity
	}

	return &Auditor{
		pubsub:            pubsub,
		trackedIdentities: trackedIdentities,
	}
}

// Audit pushes the audit message to nats.
func (a *Auditor) Audit(bctx bahamut.Context, err error) {

	if len(a.trackedIdentities) != 0 {
		trackedIdentity, ok := a.trackedIdentities[bctx.Request().Identity]
		if !ok {
			return
		}

		if len(trackedIdentity.Operations) != 0 && !slices.Contains(trackedIdentity.Operations, bctx.Request().Operation) {
			return
		}
	}

	msg := &AuditMessage{
		Operation: bctx.Request().Operation,
		Identity:  bctx.Request().Identity,
		Namespace: bctx.Request().Namespace,
		ClaimsMap: bctx.ClaimsMap(),
	}

	if err != nil {
		msg.Error = err.Error()
	}

	if err = notification.Publish(
		a.pubsub,
		NotificationAudit,
		&notification.Message{
			Type: string(msg.Operation),
			Data: msg,
		},
	); err != nil {
		slog.Error("Issue publishing audit message", err)
	}
}
