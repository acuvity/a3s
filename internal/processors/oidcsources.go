package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A OIDCSourcesProcessor is a bahamut processor for OIDCSource.
type OIDCSourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewOIDCSourcesProcessor returns a new OIDCSourcesProcessor.
func NewOIDCSourcesProcessor(manipulator manipulate.Manipulator) *OIDCSourcesProcessor {
	return &OIDCSourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.OIDCSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateOIDCSourceSecrets(obj.(*api.OIDCSource))
		}),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.OIDCSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewOIDCSource())
}

// ProcessUpdate handles the update requests for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.OIDCSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateOIDCSourceSecrets(obj.(*api.OIDCSource))
		}),
	)
}

// ProcessDelete handles the delete requests for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewOIDCSource())
}

// ProcessInfo handles the info request for OIDCSource.
func (p *OIDCSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.OIDCSourceIdentity)
}

// validateOIDCSourceSecrets checks the secret attributes of the given source.
// The attributes are transient, so elemental does not generate validation for
// them. This runs as a pre-write hook, after crud.Update has backported the
// stored secrets, so omitting them on update keeps the stored value.
func validateOIDCSourceSecrets(src *api.OIDCSource) error {
	return elemental.ValidateRequiredString("clientSecret", src.ClientSecret)
}
