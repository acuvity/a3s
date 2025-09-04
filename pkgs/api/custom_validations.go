package api

import (
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.acuvity.ai/elemental"
)

// ValidateDuration valides the given string is a parseable Go duration.
func ValidateDuration(attribute string, duration string) error {

	if duration == "" {
		return nil
	}

	if _, err := time.ParseDuration(duration); err != nil {
		return makeErr("attr", fmt.Sprintf("Attribute '%s' must be a validation duration", attribute))
	}

	return nil
}

// ValidateCIDR validates a CIDR.
func ValidateCIDR(attribute string, network string) error {

	if _, _, err := net.ParseCIDR(network); err == nil {
		return nil
	}

	return makeErr(attribute, fmt.Sprintf("Attribute '%s' must be a CIDR", attribute))
}

// ValidateCIDROptional validates an optional CIDR. It can be empty.
func ValidateCIDROptional(attribute string, network string) error {
	if len(network) == 0 {
		return nil
	}

	return ValidateCIDR(attribute, network)
}

// ValidateCIDRList validates a list of CIDRS.
// The list cannot be empty
func ValidateCIDRList(attribute string, networks []string) error {

	if len(networks) == 0 {
		return makeErr(attribute, fmt.Sprintf("Attribute '%s' must not be empty", attribute))
	}

	return ValidateCIDRListOptional(attribute, networks)
}

// ValidateCIDRListOptional validates a list of CIDRs.
// It can be empty.
func ValidateCIDRListOptional(attribute string, networks []string) error {

	for _, network := range networks {
		if err := ValidateCIDR(attribute, network); err != nil {
			return err
		}
	}

	return nil
}

// ValidateTagsExpression validates an [][]string is a valid tag expression.
func ValidateTagsExpression(attribute string, expression [][]string) error {

	for _, tags := range expression {

		for _, tag := range tags {

			if err := ValidateTag(attribute, tag); err != nil {
				return err
			}
		}
	}

	return nil
}

var tagRegex = regexp.MustCompile(`^[^= ]+=.+`)

// ValidateTag validates a single tag.
func ValidateTag(attribute string, tag string) error {

	if strings.TrimSpace(tag) != tag {
		return makeErr(attribute, fmt.Sprintf("'%s' must not contain any leading or trailing spaces", tag))
	}

	if len([]byte(tag)) >= 1024 {
		return makeErr(attribute, fmt.Sprintf("'%s' must be less than 1024 bytes", tag))
	}

	if !tagRegex.MatchString(tag) {
		return makeErr(attribute, fmt.Sprintf("'%s' must contain at least one '=' symbol separating two valid words", tag))
	}

	return nil
}

// ValidatePEM validates a string contains a PEM.
func ValidatePEM(attribute string, pemdata string) error {

	if pemdata == "" {
		return nil
	}

	var i int
	var block *pem.Block
	rest := []byte(pemdata)

	for {
		block, rest = pem.Decode(rest)

		if block == nil {
			return makeErr(attribute, fmt.Sprintf("Unable to decode PEM number %d", i))
		}

		if len(rest) == 0 {
			return nil
		}
		i++
	}
}

// ValidateIssue validates a whole issue object.
func ValidateIssue(iss *Issue) error {

	switch iss.SourceType {
	case IssueSourceTypeA3S:
		if iss.InputA3S == nil {
			return makeErr("inputA3S", "You must set inputA3S for the requested sourceType")
		}
		if iss.TokenType == IssueTokenTypeRefresh {
			return makeErr("tokenType", "You cannot ask for a resfresh token for the request source type")
		}
	case IssueSourceTypeRemoteA3S:
		if iss.InputRemoteA3S == nil {
			return makeErr("inputRemoteA3S", "You must set inputRemoteA3S for the requested sourceType")
		}
	case IssueSourceTypeAWS:
		if iss.InputAWS == nil {
			return makeErr("inputAWS", "You must set inputAWS for the requested sourceType")
		}
	case IssueSourceTypeLDAP:
		if iss.InputLDAP == nil {
			return makeErr("inputLDAP", "You must set inputLDAP for the requested sourceType")
		}
	case IssueSourceTypeGCP:
		if iss.InputGCP == nil {
			return makeErr("inputGCP", "You must set inputCGP for the requested sourceType")
		}
	case IssueSourceTypeAzure:
		if iss.InputAzure == nil {
			return makeErr("inputAzure", "You must set inputAzure for the requested sourceType")
		}
	case IssueSourceTypeOIDC:
		if iss.InputOIDC == nil {
			return makeErr("inputOIDC", "You must set inputOIDC for the requested sourceType")
		}
	case IssueSourceTypeHTTP:
		if iss.InputHTTP == nil {
			return makeErr("inputHTTP", "You must set inputHTTP for the requested sourceType")
		}
	case IssueSourceTypeSAML:
		if iss.InputSAML == nil {
			return makeErr("inputSAML", "You must set inputSAML for the requested sourceType")
		}
	}

	return nil
}

// ValidateURL validates the given value is a correct url.
func ValidateURL(attribute string, u string) error {

	uu, err := url.Parse(u)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("invalid url: %s", err))
	}

	switch uu.Scheme {
	case "http", "https":
	case "":
		return makeErr(attribute, "invalid url: missing scheme")
	default:
		return makeErr(attribute, "invalid url: invalid scheme")
	}

	return nil
}

// ValidateMTLSSource validates the given MTLSSource.
func ValidateMTLSSource(source *MTLSSource) error {

	switch source.ClaimsRetrievalMode {
	case MTLSSourceClaimsRetrievalModeEntra:
		if source.CA == "" {
			return makeErr("CA", "CA must be set when claims retrieval mode is set to 'Entra'")
		}
		if source.ClientTenantID == "" {
			return makeErr("clientTenantID", "clientTenantID must be set when claims retrieval mode is set to 'Entra'")
		}
		if source.ClientID == "" {
			return makeErr("clientID", "clientID must be set when claims retrieval mode is set to 'Entra'")
		}
		if source.ClientSecret == "" {
			return makeErr("clientSecret", "clientSecret must be set when claims retrieval mode is set to 'Entra'")
		}
	}

	return nil
}

// ValidateSAMLSource validates the given SAMLSource.
func ValidateSAMLSource(source *SAMLSource) error {

	if source.IDPMetadata != "" && source.IDPMetadataURL != "" {
		return makeErr("IDPMedata", "If IDPMetadataURL is set, you cannot set IDPMetadata")
	}

	if source.IDPMetadata != "" || source.IDPMetadataURL != "" {
		source.IDPURL = ""
		source.IDPCertificate = ""
		source.IDPIssuer = ""

		if source.IDPMetadata != "" {
			source.IDPMetadataURL = ""
		}

		if source.IDPMetadataURL != "" {
			source.IDPMetadata = ""
		}

		return nil
	}

	if source.IDPURL == "" {
		return makeErr("IDPURL", "IDPURL is required if IDPMetadata is not set")
	}

	if source.IDPIssuer == "" {
		return makeErr("IDPIssuer", "IDPIssuer is required if IDPMetadata is not set")
	}

	if source.IDPCertificate == "" {
		return makeErr("IDPCertificate", "IDPCertificate is required if IDPMetadata is not set")
	}

	return nil
}

// ValidateKeys validate the given included keys.
func ValidateKeys(attribute string, keys []string) error {

	for _, k := range keys {
		kk := strings.TrimSpace(k)
		if kk != k {
			return makeErr(attribute, fmt.Sprintf("key '%s' must not contains any leading or trailing spaces", k))
		}
	}

	return nil
}

// ValidateRevocation validates the goven given revocation.
func ValidateRevocation(rev *Revocation) error {
	if !rev.IssuedBefore.IsZero() && rev.IssuedBeforeRel != "" {
		return makeErr("issuedBefore", "issuedBeforeRel cannot be set if issuedBefore is also set.")
	}

	return nil
}

func makeErr(attribute string, message string) elemental.Error {

	err := elemental.NewError(
		"Validation Error",
		message,
		"a3s",
		http.StatusUnprocessableEntity,
	)

	if attribute != "" {
		err.Data = map[string]any{"attribute": attribute}
	}

	return err
}
