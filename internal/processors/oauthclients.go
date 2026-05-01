package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
)

// A OAuthClientsProcessor is a bahamut processor for OAuthClient.
type OAuthClientsProcessor struct {
	manipulator manipulate.Manipulator
}

// NewOAuthClientsProcessor returns a new OAuthClientsProcessor.
func NewOAuthClientsProcessor(manipulator manipulate.Manipulator) *OAuthClientsProcessor {
	return &OAuthClientsProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for OAuthClient.
func (p *OAuthClientsProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.OAuthClient))
}

// ProcessRetrieveMany handles the retrieve many requests for OAuthClient.
func (p *OAuthClientsProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.OAuthClientsList{})
}

// ProcessRetrieve handles the retrieve requests for OAuthClient.
func (p *OAuthClientsProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewOAuthClient())
}

// ProcessUpdate handles the update requests for OAuthClient.
func (p *OAuthClientsProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.OAuthClient))
}

// ProcessDelete handles the delete requests for OAuthClient.
func (p *OAuthClientsProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewOAuthClient())
}

// ProcessInfo handles the info request for OAuthClient.
func (p *OAuthClientsProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.OAuthClientIdentity)
}
