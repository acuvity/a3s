package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A LDAPSourcesProcessor is a bahamut processor for LDAPSource.
type LDAPSourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewLDAPSourcesProcessor returns a new LDAPSourcesProcessor.
func NewLDAPSourcesProcessor(manipulator manipulate.Manipulator) *LDAPSourcesProcessor {
	return &LDAPSourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.LDAPSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateLDAPSourceSecrets(obj.(*api.LDAPSource))
		}),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.LDAPSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewLDAPSource())
}

// ProcessUpdate handles the update requests for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.LDAPSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateLDAPSourceSecrets(obj.(*api.LDAPSource))
		}),
	)
}

// ProcessDelete handles the delete requests for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewLDAPSource())
}

// ProcessInfo handles the info request for LDAPSource.
func (p *LDAPSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.LDAPSourceIdentity)
}

// validateLDAPSourceSecrets checks the secret attributes of the given source.
// The attributes are transient, so elemental does not generate validation for
// them. This runs as a pre-write hook, after crud.Update has backported the
// stored secrets, so omitting them on update keeps the stored value.
func validateLDAPSourceSecrets(src *api.LDAPSource) error {
	return elemental.ValidateRequiredString("bindPassword", src.BindPassword)
}
