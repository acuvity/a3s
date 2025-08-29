package processors

import (
	"net/http"

	"go.acuvity.ai/a3s/internal/issuer/samlissuer"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A SAMLSourcesProcessor is a bahamut processor for SAMLSource.
type SAMLSourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewSAMLSourcesProcessor returns a new SAMLSourcesProcessor.
func NewSAMLSourcesProcessor(manipulator manipulate.Manipulator) *SAMLSourcesProcessor {
	return &SAMLSourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	source := bctx.InputData().(*api.SAMLSource)
	if err := samlissuer.InjectIDPMetadata(source); err != nil {
		return elemental.NewErrorWithData(
			"Bad Request",
			err.Error(),
			"a3s",
			http.StatusUnprocessableEntity,
			map[string]any{"attribute": "IDPMetadata"},
		)
	}

	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.SAMLSource))
}

// ProcessRetrieveMany handles the retrieve many requests for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.SAMLSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewSAMLSource())
}

// ProcessUpdate handles the update requests for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	source := bctx.InputData().(*api.SAMLSource)
	if err := samlissuer.InjectIDPMetadata(source); err != nil {
		return elemental.NewErrorWithData(
			"Bad Request",
			err.Error(),
			"a3s",
			http.StatusUnprocessableEntity,
			map[string]any{"attribute": "IDPMetadata"},
		)
	}

	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.SAMLSource))
}

// ProcessDelete handles the delete requests for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewSAMLSource())
}

// ProcessInfo handles the info request for SAMLSource.
func (p *SAMLSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.SAMLSourceIdentity)
}
