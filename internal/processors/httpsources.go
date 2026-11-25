package processors

import (
	"fmt"
	"net/http"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/tg/tglib"
)

// A HTTPSourcesProcessor is a bahamut processor for HTTPSource.
type HTTPSourcesProcessor struct {
	manipulator manipulate.Manipulator
}

// NewHTTPSourcesProcessor returns a new HTTPSourcesProcessor.
func NewHTTPSourcesProcessor(manipulator manipulate.Manipulator) *HTTPSourcesProcessor {
	return &HTTPSourcesProcessor{
		manipulator: manipulator,
	}
}

// ProcessCreate handles the creates requests for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.HTTPSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateHTTPSourceSecrets(obj.(*api.HTTPSource))
		}),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.HTTPSourcesList{})
}

// ProcessRetrieve handles the retrieve requests for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewHTTPSource())
}

// ProcessUpdate handles the update requests for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.HTTPSource),
		crud.OptionPreWriteHook(func(obj elemental.Identifiable, _ elemental.Identifiable) error {
			return validateHTTPSourceSecrets(obj.(*api.HTTPSource))
		}),
	)
}

// ProcessDelete handles the delete requests for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewHTTPSource())
}

// ProcessInfo handles the info request for HTTPSource.
func (p *HTTPSourcesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.HTTPSourceIdentity)
}

// validateHTTPSourceSecrets checks the secret attributes of the given source.
// The attributes are transient, so elemental does not generate validation for
// them. This runs as a pre-write hook, after crud.Update has backported the
// stored secrets, so omitting them on update keeps the stored value, and the
// key is checked against the certificate that will actually be stored.
func validateHTTPSourceSecrets(src *api.HTTPSource) error {

	if err := elemental.ValidateRequiredString("key", src.Key); err != nil {
		return err
	}

	if err := api.ValidatePEM("key", src.Key); err != nil {
		return err
	}

	// This is the same call the http issuer makes at login. Doing it here
	// rejects a key that does not match the certificate when the source is
	// saved, instead of failing every login later.
	if _, _, err := tglib.ReadCertificate([]byte(src.Certificate), []byte(src.Key), ""); err != nil {
		e := elemental.NewError(
			"Validation Error",
			fmt.Sprintf("Attribute 'key' must be the private key of the certificate: %s", err),
			"a3s",
			http.StatusUnprocessableEntity,
		)
		e.Data = map[string]any{"attribute": "key"}
		return e
	}

	return nil
}
