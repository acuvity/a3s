package mtlsissuer

import (
	"crypto/x509"
	"fmt"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
)

func getPrincipalName(iss *mtlsIssuer, cert *x509.Certificate) (string, error) {

	switch iss.source.PrincipalUserX509Field {

	case api.MTLSSourcePrincipalUserX509FieldCommonName:
		return cert.Subject.CommonName, nil

	case api.MTLSSourcePrincipalUserX509FieldEmail:
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0], nil
		} else {
			return "", fmt.Errorf("unable to find any email addresses in the user certificate")
		}

	default:
		panic("invalid mtls source principal user field")
	}
}

func makeErrMaker(provider string) func(title string, desc string, code int) error {
	return func(title string, desc string, code int) error {
		return elemental.NewError(title, desc, "a3s:mtlssource:"+provider, code)
	}
}
