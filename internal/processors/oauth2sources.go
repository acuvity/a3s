package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A OAuth2SourcesProcessor is a bahamut processor for OAuth2Source.
type OAuth2SourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewOAuth2SourcesProcessor returns a new OAuth2SourcesProcessor.
func NewOAuth2SourcesProcessor(manipulator manipulate.Manipulator) *OAuth2SourcesProcessor {
	return &OAuth2SourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.OAuth2Source),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateOAuth2SourceSecrets(obj.(*api.OAuth2Source))
		}),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.OAuth2SourcesList{})
}

// ProcessRetrieve handles the retrieve requests for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewOAuth2Source())
}

// ProcessUpdate handles the update requests for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.OAuth2Source),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateOAuth2SourceSecrets(obj.(*api.OAuth2Source))
		}),
	)
}

// ProcessDelete handles the delete requests for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewOAuth2Source())
}

// ProcessInfo handles the info request for OAuth2Source.
func (p *OAuth2SourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.OAuth2SourceIdentity)
}

// validateOAuth2SourceSecrets checks the secret attributes of the given source.
// The attributes are transient, so elemental does not generate validation for
// them. This runs as a pre-write hook, after crud.Update has backported the
// stored secrets, so omitting them on update keeps the stored value.
func validateOAuth2SourceSecrets(src *api.OAuth2Source) error {
	return elemental.ValidateRequiredString("clientSecret", src.ClientSecret)
}
