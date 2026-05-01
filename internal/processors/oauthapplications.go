package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
)

// A OAuthApplicationsProcessor is a bahamut processor for OAuthApplication.
type OAuthApplicationsProcessor struct {
	manipulator manipulate.Manipulator
}

// NewOAuthApplicationsProcessor returns a new OAuthApplicationsProcessor.
func NewOAuthApplicationsProcessor(manipulator manipulate.Manipulator) *OAuthApplicationsProcessor {
	return &OAuthApplicationsProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.OAuthApplication))
}

// ProcessRetrieveMany handles the retrieve many requests for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.OAuthApplicationsList{})
}

// ProcessRetrieve handles the retrieve requests for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewOAuthApplication())
}

// ProcessUpdate handles the update requests for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.OAuthApplication))
}

// ProcessDelete handles the delete requests for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewOAuthApplication())
}

// ProcessInfo handles the info request for OAuthApplication.
func (p *OAuthApplicationsProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.OAuthApplicationIdentity)
}
