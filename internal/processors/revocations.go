package processors

import (
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A RevocationProcessor is a bahamut processor for Revocation.
type RevocationProcessor struct {
	manipulator manipulate.Manipulator
	pubsub      bahamut.PubSubClient
}

// NewRevocationsProcessor returns a new RevocationProcessor.
func NewRevocationsProcessor(manipulator manipulate.Manipulator, pubsub bahamut.PubSubClient) *RevocationProcessor {
	return &RevocationProcessor{
		manipulator: manipulator,
		pubsub:      pubsub,
	}
}

// ProcessCreate handles the creates requests for Revocation.
func (p *RevocationProcessor) ProcessCreate(bctx bahamut.Context) error {

	revocation := bctx.InputData().(*api.Revocation)
	if revocation.Expiration.IsZero() {
		revocation.Expiration = time.Now().Add(8765 * time.Hour)
	}

	return crud.Create(
		bctx,
		p.manipulator,
		bctx.InputData().(*api.Revocation),
		crud.OptionPreWriteHook(p.makePreHook()),
		crud.OptionPostWriteHook(p.makeNotify()),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for Revocation.
func (p *RevocationProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.RevocationsList{})
}

// ProcessRetrieve handles the retrieve requests for Revocation.
func (p *RevocationProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewRevocation())
}

// ProcessDelete handles the delete requests for Revocation.
func (p *RevocationProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewRevocation(),
		crud.OptionPostWriteHook(p.makeNotify()),
	)
}

// ProcessInfo handles the info request for Revocation.
func (p *RevocationProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.RevocationIdentity)
}

func (p *RevocationProcessor) makeNotify() crud.PostWriteHook {
	return func(obj elemental.Identifiable) {
		_ = notification.Publish(
			p.pubsub,
			nscache.NotificationNamespaceChanges,
			&notification.Message{
				Data: obj.(*api.Revocation).Namespace,
			},
		)
	}
}

func (p *RevocationProcessor) makePreHook() crud.PreWriteHook {
	return func(obj elemental.Identifiable, original elemental.Identifiable) error {
		rev := obj.(*api.Revocation)
		rev.FlattenedSubject = flattenTags(rev.Subject)
		return nil
	}
}
