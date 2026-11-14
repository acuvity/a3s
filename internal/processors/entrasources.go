package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
)

// A EntraSourcesProcessor is a bahamut processor for EntraSource.
type EntraSourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewEntraSourcesProcessor returns a new EntraSourcesProcessor.
func NewEntraSourcesProcessor(manipulator manipulate.Manipulator) *EntraSourcesProcessor {
	return &EntraSourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for EntraSource.
func (p *EntraSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.EntraSource))
}

// ProcessRetrieveMany handles the retrieve many requests for EntraSource.
func (p *EntraSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.EntraSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for EntraSource.
func (p *EntraSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewEntraSource())
}

// ProcessUpdate handles the update requests for EntraSource.
func (p *EntraSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.EntraSource))
}

// ProcessDelete handles the delete requests for EntraSource.
func (p *EntraSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewEntraSource())
}

// ProcessInfo handles the info request for EntraSource.
func (p *EntraSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.EntraSourceIdentity)
}
