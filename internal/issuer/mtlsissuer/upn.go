package mtlsissuer

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

// oidMicrosoftUPN is the ID for Microsoft UPN
var oidMicrosoftUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

// oidSubjectAlternativeName is the ID for the Subject Alternative Name
var oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}

// getUPNFromCert returns the Microsoft UPN from cert.
func getUPNFromCert(cert *x509.Certificate) (string, error) {

	var extensionValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAlternativeName) {
			extensionValue = ext.Value
			break
		}
	}

	if len(extensionValue) == 0 {
		return "", nil
	}

	var raw asn1.RawValue
	_, err := asn1.Unmarshal(extensionValue, &raw)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal SAN top-level: %w", err)
	}

	remaining := raw.Bytes
	for len(remaining) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &raw)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal GeneralName: %w", err)
		}

		if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 {
			remaining = rest
			continue
		}

		var oid asn1.ObjectIdentifier
		rest2, err := asn1.Unmarshal(raw.Bytes, &oid)
		if err != nil {
			return "", fmt.Errorf("unable to parse unmarhsal oid: %w", err)
		}

		if !oid.Equal(oidMicrosoftUPN) {
			continue
		}

		var val asn1.RawValue
		if _, err := asn1.Unmarshal(rest2, &val); err != nil {
			return "", fmt.Errorf("unable to parse unmarhsal value: %w", err)
		}

		var upn string
		if _, err := asn1.Unmarshal(val.Bytes, &upn); err != nil {
			return "", fmt.Errorf("found Microsoft UPN OID but failed to decode value: %w (raw base64=%s)",
				err, base64.StdEncoding.EncodeToString(val.Bytes))
		}

		return upn, nil
	}

	// No UPN found
	return "", nil
}
