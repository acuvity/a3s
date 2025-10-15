package processors

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/internal/idp/entra"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/tg/tglib"
)

// A MTLSSourcesProcessor is a bahamut processor for MTLSSource.
type MTLSSourcesProcessor struct {
	manipulator manipulate.Manipulator
	pubsub      bahamut.PubSubClient
}

// NewMTLSSourcesProcessor returns a new MTLSSourcesProcessor.
func NewMTLSSourcesProcessor(manipulator manipulate.Manipulator, pubsub bahamut.PubSubClient) *MTLSSourcesProcessor {
	return &MTLSSourcesProcessor{
		manipulator: manipulator,
		pubsub:      pubsub,
	}
}

// ProcessCreate handles the creates requests for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	notify := p.makeNotify(elemental.OperationCreate)
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.MTLSSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, orig elemental.Identifiable) error {
			insertEntraSecrets(obj.(*api.MTLSSource), nil)
			return insertTLSReferences(obj.(*api.MTLSSource))
		}),
		crud.OptionPostWriteHook(func(obj elemental.Identifiable) {
			notify(obj)
		}),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.MTLSSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewMTLSSource())
}

// ProcessUpdate handles the update requests for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	notify := p.makeNotify(elemental.OperationUpdate)
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.MTLSSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, orig elemental.Identifiable) error {
			insertEntraSecrets(obj.(*api.MTLSSource), orig.(*api.MTLSSource))
			return insertTLSReferences(obj.(*api.MTLSSource))
		}),
		crud.OptionPostWriteHook(func(obj elemental.Identifiable) {
			notify(obj)
		}),
	)
}

// ProcessDelete handles the delete requests for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	notify := p.makeNotify(elemental.OperationDelete)
	return crud.Delete(bctx, p.manipulator, api.NewMTLSSource(),
		crud.OptionPostWriteHook(func(obj elemental.Identifiable) {
			notify(obj)
		}),
	)
}

// ProcessInfo handles the info request for MTLSSource.
func (p *MTLSSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.MTLSSourceIdentity)
}

func (p *MTLSSourcesProcessor) makeNotify(op elemental.Operation) crud.PostWriteHook {
	return func(obj elemental.Identifiable) {

		src := obj.(*api.MTLSSource)

		if src.EntraApplicationCredentials == nil {
			return
		}

		out, err := bson.Marshal(obj)
		if err != nil {
			slog.Error("Unable to encode MTLS source to BSON", err)
			return
		}

		if err := notification.Publish(
			p.pubsub,
			entra.NotificationEntraSyncerUpdateSubscriptions,
			&notification.Message{
				Type: string(op),
				// we pass the full object in bson to keep all secret attributes during encoding.
				Data: base64.StdEncoding.EncodeToString(out),
			},
		); err != nil {
			slog.Error("Unable to send MTLS entra sysnotif", "topic", entra.NotificationEntraSyncerUpdateSubscriptions, err)
		}
	}
}

func insertTLSReferences(src *api.MTLSSource) error {

	certs, err := tglib.ParseCertificates([]byte(src.CA))
	if err != nil {
		return err
	}

	src.Fingerprints = make([]string, len(certs))
	src.SubjectKeyIDs = make([]string, len(certs))
	for i, cert := range certs {
		src.Fingerprints[i] = token.Fingerprint(cert)
		src.SubjectKeyIDs[i] = fmt.Sprintf("%02X", cert.SubjectKeyId)
	}

	return nil
}

func insertEntraSecrets(src *api.MTLSSource, orig *api.MTLSSource) {

	switch src.ClaimsRetrievalMode {
	case api.MTLSSourceClaimsRetrievalModeEntra:
		src.OktaApplicationCredentials = nil
	case api.MTLSSourceClaimsRetrievalModeOkta:
		src.EntraApplicationCredentials = nil
	default:
		src.OktaApplicationCredentials = nil
		src.EntraApplicationCredentials = nil
	}

	installGraphEvents := func() {
		b := make([]byte, 64)
		if _, err := rand.Read(b); err != nil {
			panic(fmt.Sprintf("unable to generate random secret: %s", err))
		}
		src.EntraApplicationCredentials.GraphEventSecret = fmt.Sprintf("%x", b)
		src.EntraApplicationCredentials.GraphSubscriptionIDs = nil
		src.EntraApplicationCredentials.GraphSubscriptionExpiration = time.Time{}
	}

	uninstallGraphEvents := func() {
		if src.EntraApplicationCredentials != nil {
			src.EntraApplicationCredentials.GraphEventSecret = ""
			src.EntraApplicationCredentials.GraphSubscriptionIDs = nil
			src.EntraApplicationCredentials.GraphSubscriptionExpiration = time.Time{}
		}
	}

	ncreds := src.EntraApplicationCredentials
	var ocreds *api.MTLSSourceEntra
	if orig != nil {
		ocreds = orig.EntraApplicationCredentials
	}

	// if entra is not on and has not been turned on, we do nothing
	if ocreds == nil && ncreds == nil {
		return
	}

	// if entra was turned off, uninstall
	if ocreds != nil && ncreds == nil {
		uninstallGraphEvents()
		return
	}

	// if entra was turned on with graph event enabled
	if ocreds == nil && ncreds != nil && ncreds.GraphEventsEnabled {
		installGraphEvents()
		return
	}

	// Now, if entra was already on
	if ocreds != nil && ncreds != nil {

		// if graph event was turned off
		if ocreds.GraphEventsEnabled && !ncreds.GraphEventsEnabled {
			uninstallGraphEvents()
			return
		}

		// if graph event was turned on
		if !ocreds.GraphEventsEnabled && ncreds.GraphEventsEnabled {
			installGraphEvents()
			return
		}
	}
}
