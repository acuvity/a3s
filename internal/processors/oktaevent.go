package processors

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A OktaEventsProcessor is a bahamut processor for OktaEvents.
type OktaEventsProcessor struct {
	manipulator manipulate.TransactionalManipulator
}

// NewOktaEventsProcessor returns a new OktaEventsProcessor.
func NewOktaEventsProcessor(manipulator manipulate.TransactionalManipulator) *OktaEventsProcessor {

	return &OktaEventsProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for OktaEvents.
func (p *OktaEventsProcessor) ProcessCreate(bctx bahamut.Context) error {

	evt := bctx.InputData().(*api.OktaEvent)

	if evt.Payload == "" {
		return elemental.NewError("Bad Request", "Received an OktaEvent with an empty payload", "a3s", http.StatusBadRequest)
	}

	payload := &oktaPayload{}
	if err := elemental.Decode(elemental.EncodingTypeJSON, []byte(evt.Payload), payload); err != nil {
		return elemental.NewError("Bad Request", fmt.Sprintf("Unable to decode okta event payload: %s", err), "a3s", http.StatusBadRequest)
	}

	ns := bctx.Request().Namespace

	for _, evt := range payload.Data.Events {

		switch evt.EventType {

		case "group.user_membership.add", "group.user_membership.remove":

			for _, t := range evt.Targets {
				if t.Type != "User" {
					continue
				}
				p.invalidateTokensMacthing(bctx.Context(), ns, []string{fmt.Sprintf("login=%s", t.AlternateID)})
			}

		case "group.lifecycle.delete":

			for _, t := range evt.Targets {
				if t.Type != "UserGroup" {
					continue
				}
				p.invalidateTokensMacthing(bctx.Context(), ns, []string{fmt.Sprintf("group=%s", t.DisplayName)})
			}

		case "group.profile.update":

			for _, t := range evt.Targets {
				if t.Type != "UserGroup" {
					continue
				}
				// TODO: We don't get the previous state.
			}

		case "user.lifecycle.delete.initiated", "user.lifecycle.suspend", "user.lifecycle.deactivate":

			for _, t := range evt.Targets {

				if t.Type != "User" {
					continue
				}
				p.invalidateTokensMacthing(bctx.Context(), ns, []string{fmt.Sprintf("login=%s", t.AlternateID)})
			}
		}
	}

	return nil
}

func (p *OktaEventsProcessor) invalidateTokensMacthing(ctx context.Context, namespace string, claims []string) {

	fclaims := append([]string{
		"@source:type=mtls",
	}, claims...)

	revoke := makeEventTriggeredRevocation(fclaims, namespace)

	if err := p.manipulator.Create(manipulate.NewContext(ctx), revoke); err != nil {
		slog.Error("Unable to revoke okta tokens", "namespace", namespace, "revoked", fclaims, err)
		return
	}

	slog.Info("OktaEvent triggered tokens revocation", "namespace", namespace, "revoked", fclaims)
}

type oktaResource struct {
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
}

type oktaEvent struct {
	EventType string         `json:"eventType"`
	Targets   []oktaResource `json:"target"`
}

type oktaPayload struct {
	Data struct {
		Events []oktaEvent `json:"events"`
	} `json:"data"`
}
