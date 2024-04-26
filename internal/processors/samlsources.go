package processors

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"

	types "github.com/russellhaering/gosaml2/types"
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
	if err := injectIDPMetadata(source); err != nil {
		return err
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
	if err := injectIDPMetadata(source); err != nil {
		return err
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

func injectIDPMetadata(source *api.SAMLSource) error {

	if source.IDPMetadata == "" {
		return nil
	}

	data := []byte(source.IDPMetadata)

	descriptor := &types.EntityDescriptor{}
	if err := xml.Unmarshal(data, descriptor); err != nil {
		return elemental.NewErrorWithData(
			"Bad Request",
			fmt.Sprintf("unable to read xml content %s", source.IDPMetadata),
			"a3s",
			http.StatusUnprocessableEntity,
			map[string]interface{}{"attribute": "IDPMetadata"},
		)
	}

	if descriptor.IDPSSODescriptor != nil && len(descriptor.IDPSSODescriptor.SingleSignOnServices) > 0 {

		source.IDPURL = descriptor.IDPSSODescriptor.SingleSignOnServices[0].Location
		source.IDPIssuer = descriptor.EntityID

		for _, kd := range descriptor.IDPSSODescriptor.KeyDescriptors {
			for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
				if xcert.Data == "" {
					return elemental.NewErrorWithData(
						"Bad Request",
						fmt.Sprintf("metadata certificate at index %d must not be empty", idx),
						"a3s",
						http.StatusUnprocessableEntity,
						map[string]interface{}{"attribute": "IDPMetadata"},
					)
				}

				certData, err := base64.StdEncoding.DecodeString(xcert.Data)
				if err != nil {
					return elemental.NewErrorWithData(
						"Bad Request",
						fmt.Sprintf("undable to decode metadata certificate at index %d: %s", idx, err),
						"a3s",
						http.StatusUnprocessableEntity,
						map[string]interface{}{"attribute": "IDPMetadata"},
					)
				}

				source.IDPCertificate = string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certData,
				}))
			}
		}
	} else if descriptor.SPSSODescriptor != nil && len(descriptor.SPSSODescriptor.AssertionConsumerServices) > 0 {
		source.IDPURL = descriptor.SPSSODescriptor.AssertionConsumerServices[0].Location
		source.IDPIssuer = descriptor.EntityID
	}

	source.IDPMetadata = ""

	return nil
}
