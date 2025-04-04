package push

import (
	"fmt"
	"log/slog"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/authorizer"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

var pushSessionIdentity = "pushsession"

type pushedEntity struct {
	ID                string `msgpack:"ID" json:"ID"`
	Namespace         string `msgpack:"namespace" json:"namespace"`
	Name              string `msgpack:"name" json:"name"`
	Propagate         bool   `msgpack:"propagate" json:"propagate"`
	PropagationHidden bool   `msgpack:"propagationHidden" json:"propagationHidden"`
}

// A dispatcher handles dispatching events to push sessions.
type dispatcher struct {
	authorizer authorizer.Authorizer
}

// NewDispatcher returns a new PushDispatchHandler.
func NewDispatcher(authorizer authorizer.Authorizer) bahamut.PushDispatchHandler {

	return &dispatcher{
		authorizer: authorizer,
	}
}

// OnPushSessionInit is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) OnPushSessionInit(session bahamut.PushSession) (bool, error) {

	restrictions, err := permissions.GetRestrictions(token.FromSession(session))
	if err != nil {
		return false, err
	}

	ok, err := g.authorizer.CheckAuthorization(
		session.Context(),
		session.Claims(),
		"get",
		session.Parameter("namespace"),
		pushSessionIdentity,
		authorizer.OptionCheckSourceIP(session.ClientIP()),
		authorizer.OptionCheckRestrictions(restrictions),
	)

	if err != nil {
		slog.Error("Unable to authorize session", err)
		return false, err
	}

	return ok, nil
}

// OnPushSessionStart is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) OnPushSessionStart(session bahamut.PushSession) {
	slog.Debug("Push session started", "claims", session.Claims())
}

// OnPushSessionStop is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) OnPushSessionStop(session bahamut.PushSession) {
	slog.Debug("Push session stopped", "claims", session.Claims())
}

// SummarizeEvent is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) SummarizeEvent(event *elemental.Event) (any, error) {

	entity := pushedEntity{}
	if err := event.Decode(&entity); err != nil {
		return nil, fmt.Errorf("unable to summarize event entity: %w", err)
	}

	return entity, nil
}

// RelatedEventIdentities is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) RelatedEventIdentities(identity string) []string {
	return nil
}

// ShouldDispatch is part of the bahamut.PushDispatchHandler interface
func (g *dispatcher) ShouldDispatch(session bahamut.PushSession, event *elemental.Event, summary any) (bool, error) {

	entity := summary.(pushedEntity)
	sessionNS := session.Parameter("namespace")

	isFromCurrentNS := entity.Namespace == sessionNS
	isFromParentNS := elemental.IsNamespaceParentOfNamespace(entity.Namespace, sessionNS)
	isFromChildNS := elemental.IsNamespaceChildrenOfNamespace(entity.Namespace, sessionNS)
	isRecursive := session.Parameter("mode") == "all"

	// If it's a ns delete, then all authorization are already voided,
	// we just push the event to the clients so they know it's gone.
	if event.Identity == api.NamespaceIdentity.Name &&
		event.Type == elemental.EventDelete &&
		(entity.Name == sessionNS || isFromParentNS) {
		return true, nil
	}

	// If the object is in a parent namespace or in a child namespace
	// and it's not in recursive mode, we don't push unless it is propagating.
	if !(isFromCurrentNS || (isFromChildNS && isRecursive)) { // nolint

		// If the object is not from a parent NS, we don't push.
		if !isFromParentNS {
			return false, nil
		}

		// If the object does not propagate or propagation is hidden, we don't push.
		if !entity.Propagate || entity.PropagationHidden {
			return false, nil
		}
	}

	// Finally we check if the session has the right to read
	// the object that is about to be pushed.
	restrictions, err := permissions.GetRestrictions(token.FromSession(session))
	if err != nil {
		return false, err
	}

	return g.authorizer.CheckAuthorization(
		session.Context(),
		session.Claims(),
		"get",
		sessionNS,
		event.Identity,
		authorizer.OptionCheckRestrictions(restrictions),
		authorizer.OptionCheckSourceIP(session.ClientIP()),
	)
}
