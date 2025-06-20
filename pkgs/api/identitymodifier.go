// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"
	"slices"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// IdentityModifierMethodValue represents the possible values for attribute "method".
type IdentityModifierMethodValue string

const (
	// IdentityModifierMethodGET represents the value GET.
	IdentityModifierMethodGET IdentityModifierMethodValue = "GET"

	// IdentityModifierMethodPATCH represents the value PATCH.
	IdentityModifierMethodPATCH IdentityModifierMethodValue = "PATCH"

	// IdentityModifierMethodPOST represents the value POST.
	IdentityModifierMethodPOST IdentityModifierMethodValue = "POST"

	// IdentityModifierMethodPUT represents the value PUT.
	IdentityModifierMethodPUT IdentityModifierMethodValue = "PUT"
)

// IdentityModifierIdentity represents the Identity of the object.
var IdentityModifierIdentity = elemental.Identity{
	Name:     "identitymodifier",
	Category: "identitymodifier",
	Package:  "a3s",
	Private:  false,
}

// IdentityModifiersList represents a list of IdentityModifiers
type IdentityModifiersList []*IdentityModifier

// Identity returns the identity of the objects in the list.
func (o IdentityModifiersList) Identity() elemental.Identity {

	return IdentityModifierIdentity
}

// Copy returns a pointer to a copy the IdentityModifiersList.
func (o IdentityModifiersList) Copy() elemental.Identifiables {

	out := slices.Clone(o)
	return &out
}

// Append appends the objects to the a new copy of the IdentityModifiersList.
func (o IdentityModifiersList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*IdentityModifier))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o IdentityModifiersList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o IdentityModifiersList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the IdentityModifiersList converted to SparseIdentityModifiersList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o IdentityModifiersList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseIdentityModifiersList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToSparse(fields...).(*SparseIdentityModifier)
	}

	return out
}

// Version returns the version of the content.
func (o IdentityModifiersList) Version() int {

	return 1
}

// IdentityModifier represents the model of a identitymodifier
type IdentityModifier struct {
	// CA to use to validate the identity modfier service.
	CA string `json:"CA,omitempty" msgpack:"CA,omitempty" bson:"ca,omitempty" mapstructure:"CA,omitempty"`

	// URL of the remote service. This URL will receive a call containing the
	// claims that are about to be delivered. It must reply with 204 if it does not
	// wish to modify the claims, or 200 alongside a body containing the modified
	// claims.
	URL string `json:"URL" msgpack:"URL" bson:"url" mapstructure:"URL,omitempty"`

	// Client certificate required to call URL. A3S will refuse to send data if the
	// endpoint does not support client certificate authentication.
	Certificate string `json:"certificate" msgpack:"certificate" bson:"certificate" mapstructure:"certificate,omitempty"`

	// Key associated to the client certificate.
	Key string `json:"key" msgpack:"key" bson:"key" mapstructure:"key,omitempty"`

	// The HTTP method to use to call the endpoint. For POST/PUT/PATCH the remote
	// server will receive the claims as a JSON encoded array in the body. For a GET,
	// the claims will be passed as a query parameter named `claim`.
	Method IdentityModifierMethodValue `json:"method" msgpack:"method" bson:"method" mapstructure:"method,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewIdentityModifier returns a new *IdentityModifier
func NewIdentityModifier() *IdentityModifier {

	return &IdentityModifier{
		ModelVersion: 1,
		Method:       IdentityModifierMethodPOST,
	}
}

// Identity returns the Identity of the object.
func (o *IdentityModifier) Identity() elemental.Identity {

	return IdentityModifierIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *IdentityModifier) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *IdentityModifier) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *IdentityModifier) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesIdentityModifier{}

	s.CA = o.CA
	s.URL = o.URL
	s.Certificate = o.Certificate
	s.Key = o.Key
	s.Method = o.Method

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *IdentityModifier) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesIdentityModifier{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.CA = s.CA
	o.URL = s.URL
	o.Certificate = s.Certificate
	o.Key = s.Key
	o.Method = s.Method

	return nil
}

// Version returns the hardcoded version of the model.
func (o *IdentityModifier) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *IdentityModifier) BleveType() string {

	return "identitymodifier"
}

// DefaultOrder returns the list of default ordering fields.
func (o *IdentityModifier) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *IdentityModifier) Doc() string {

	return `Information about a remote endpoint to call to eventually modify the identity
claims about to be issued when using the parent source.`
}

func (o *IdentityModifier) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *IdentityModifier) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseIdentityModifier{
			CA:          &o.CA,
			URL:         &o.URL,
			Certificate: &o.Certificate,
			Key:         &o.Key,
			Method:      &o.Method,
		}
	}

	sp := &SparseIdentityModifier{}
	for _, f := range fields {
		switch f {
		case "CA":
			sp.CA = &(o.CA)
		case "URL":
			sp.URL = &(o.URL)
		case "certificate":
			sp.Certificate = &(o.Certificate)
		case "key":
			sp.Key = &(o.Key)
		case "method":
			sp.Method = &(o.Method)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseIdentityModifier to the object.
func (o *IdentityModifier) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseIdentityModifier)
	if so.CA != nil {
		o.CA = *so.CA
	}
	if so.URL != nil {
		o.URL = *so.URL
	}
	if so.Certificate != nil {
		o.Certificate = *so.Certificate
	}
	if so.Key != nil {
		o.Key = *so.Key
	}
	if so.Method != nil {
		o.Method = *so.Method
	}
}

// DeepCopy returns a deep copy if the IdentityModifier.
func (o *IdentityModifier) DeepCopy() *IdentityModifier {

	if o == nil {
		return nil
	}

	out := &IdentityModifier{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *IdentityModifier.
func (o *IdentityModifier) DeepCopyInto(out *IdentityModifier) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy IdentityModifier: %s", err))
	}

	*out = *target.(*IdentityModifier)
}

// Validate valides the current information stored into the structure.
func (o *IdentityModifier) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := ValidatePEM("CA", o.CA); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("URL", o.URL); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateURL("URL", o.URL); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("certificate", o.Certificate); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidatePEM("certificate", o.Certificate); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("key", o.Key); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidatePEM("key", o.Key); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("method", string(o.Method)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("method", string(o.Method), []string{"GET", "POST", "PUT", "PATCH"}, false); err != nil {
		errors = errors.Append(err)
	}

	if len(requiredErrors) > 0 {
		return requiredErrors
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// SpecificationForAttribute returns the AttributeSpecification for the given attribute name key.
func (*IdentityModifier) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := IdentityModifierAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return IdentityModifierLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*IdentityModifier) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return IdentityModifierAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *IdentityModifier) ValueForAttribute(name string) any {

	switch name {
	case "CA":
		return o.CA
	case "URL":
		return o.URL
	case "certificate":
		return o.Certificate
	case "key":
		return o.Key
	case "method":
		return o.Method
	}

	return nil
}

// IdentityModifierAttributesMap represents the map of attribute for IdentityModifier.
var IdentityModifierAttributesMap = map[string]elemental.AttributeSpecification{
	"CA": {
		AllowedChoices: []string{},
		BSONFieldName:  "ca",
		ConvertedName:  "CA",
		Description:    `CA to use to validate the identity modfier service.`,
		Exposed:        true,
		Name:           "CA",
		Stored:         true,
		Type:           "string",
	},
	"URL": {
		AllowedChoices: []string{},
		BSONFieldName:  "url",
		ConvertedName:  "URL",
		Description: `URL of the remote service. This URL will receive a call containing the
claims that are about to be delivered. It must reply with 204 if it does not
wish to modify the claims, or 200 alongside a body containing the modified
claims.`,
		Exposed:  true,
		Name:     "URL",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"Certificate": {
		AllowedChoices: []string{},
		BSONFieldName:  "certificate",
		ConvertedName:  "Certificate",
		Description: `Client certificate required to call URL. A3S will refuse to send data if the
endpoint does not support client certificate authentication.`,
		Exposed:  true,
		Name:     "certificate",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"Key": {
		AllowedChoices: []string{},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `Key associated to the client certificate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"Method": {
		AllowedChoices: []string{"GET", "POST", "PUT", "PATCH"},
		BSONFieldName:  "method",
		ConvertedName:  "Method",
		DefaultValue:   IdentityModifierMethodPOST,
		Description: `The HTTP method to use to call the endpoint. For POST/PUT/PATCH the remote
server will receive the claims as a JSON encoded array in the body. For a GET,
the claims will be passed as a query parameter named ` + "`" + `claim` + "`" + `.`,
		Exposed:  true,
		Name:     "method",
		Required: true,
		Stored:   true,
		Type:     "enum",
	},
}

// IdentityModifierLowerCaseAttributesMap represents the map of attribute for IdentityModifier.
var IdentityModifierLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"ca": {
		AllowedChoices: []string{},
		BSONFieldName:  "ca",
		ConvertedName:  "CA",
		Description:    `CA to use to validate the identity modfier service.`,
		Exposed:        true,
		Name:           "CA",
		Stored:         true,
		Type:           "string",
	},
	"url": {
		AllowedChoices: []string{},
		BSONFieldName:  "url",
		ConvertedName:  "URL",
		Description: `URL of the remote service. This URL will receive a call containing the
claims that are about to be delivered. It must reply with 204 if it does not
wish to modify the claims, or 200 alongside a body containing the modified
claims.`,
		Exposed:  true,
		Name:     "URL",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"certificate": {
		AllowedChoices: []string{},
		BSONFieldName:  "certificate",
		ConvertedName:  "Certificate",
		Description: `Client certificate required to call URL. A3S will refuse to send data if the
endpoint does not support client certificate authentication.`,
		Exposed:  true,
		Name:     "certificate",
		Required: true,
		Stored:   true,
		Type:     "string",
	},
	"key": {
		AllowedChoices: []string{},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `Key associated to the client certificate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"method": {
		AllowedChoices: []string{"GET", "POST", "PUT", "PATCH"},
		BSONFieldName:  "method",
		ConvertedName:  "Method",
		DefaultValue:   IdentityModifierMethodPOST,
		Description: `The HTTP method to use to call the endpoint. For POST/PUT/PATCH the remote
server will receive the claims as a JSON encoded array in the body. For a GET,
the claims will be passed as a query parameter named ` + "`" + `claim` + "`" + `.`,
		Exposed:  true,
		Name:     "method",
		Required: true,
		Stored:   true,
		Type:     "enum",
	},
}

// SparseIdentityModifiersList represents a list of SparseIdentityModifiers
type SparseIdentityModifiersList []*SparseIdentityModifier

// Identity returns the identity of the objects in the list.
func (o SparseIdentityModifiersList) Identity() elemental.Identity {

	return IdentityModifierIdentity
}

// Copy returns a pointer to a copy the SparseIdentityModifiersList.
func (o SparseIdentityModifiersList) Copy() elemental.Identifiables {

	copy := slices.Clone(o)
	return &copy
}

// Append appends the objects to the a new copy of the SparseIdentityModifiersList.
func (o SparseIdentityModifiersList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*SparseIdentityModifier))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseIdentityModifiersList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseIdentityModifiersList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseIdentityModifiersList converted to IdentityModifiersList.
func (o SparseIdentityModifiersList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseIdentityModifiersList) Version() int {

	return 1
}

// SparseIdentityModifier represents the sparse version of a identitymodifier.
type SparseIdentityModifier struct {
	// CA to use to validate the identity modfier service.
	CA *string `json:"CA,omitempty" msgpack:"CA,omitempty" bson:"ca,omitempty" mapstructure:"CA,omitempty"`

	// URL of the remote service. This URL will receive a call containing the
	// claims that are about to be delivered. It must reply with 204 if it does not
	// wish to modify the claims, or 200 alongside a body containing the modified
	// claims.
	URL *string `json:"URL,omitempty" msgpack:"URL,omitempty" bson:"url,omitempty" mapstructure:"URL,omitempty"`

	// Client certificate required to call URL. A3S will refuse to send data if the
	// endpoint does not support client certificate authentication.
	Certificate *string `json:"certificate,omitempty" msgpack:"certificate,omitempty" bson:"certificate,omitempty" mapstructure:"certificate,omitempty"`

	// Key associated to the client certificate.
	Key *string `json:"key,omitempty" msgpack:"key,omitempty" bson:"key,omitempty" mapstructure:"key,omitempty"`

	// The HTTP method to use to call the endpoint. For POST/PUT/PATCH the remote
	// server will receive the claims as a JSON encoded array in the body. For a GET,
	// the claims will be passed as a query parameter named `claim`.
	Method *IdentityModifierMethodValue `json:"method,omitempty" msgpack:"method,omitempty" bson:"method,omitempty" mapstructure:"method,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseIdentityModifier returns a new  SparseIdentityModifier.
func NewSparseIdentityModifier() *SparseIdentityModifier {
	return &SparseIdentityModifier{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseIdentityModifier) Identity() elemental.Identity {

	return IdentityModifierIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseIdentityModifier) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseIdentityModifier) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseIdentityModifier) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseIdentityModifier{}

	if o.CA != nil {
		s.CA = o.CA
	}
	if o.URL != nil {
		s.URL = o.URL
	}
	if o.Certificate != nil {
		s.Certificate = o.Certificate
	}
	if o.Key != nil {
		s.Key = o.Key
	}
	if o.Method != nil {
		s.Method = o.Method
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseIdentityModifier) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseIdentityModifier{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	if s.CA != nil {
		o.CA = s.CA
	}
	if s.URL != nil {
		o.URL = s.URL
	}
	if s.Certificate != nil {
		o.Certificate = s.Certificate
	}
	if s.Key != nil {
		o.Key = s.Key
	}
	if s.Method != nil {
		o.Method = s.Method
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseIdentityModifier) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseIdentityModifier) ToPlain() elemental.PlainIdentifiable {

	out := NewIdentityModifier()
	if o.CA != nil {
		out.CA = *o.CA
	}
	if o.URL != nil {
		out.URL = *o.URL
	}
	if o.Certificate != nil {
		out.Certificate = *o.Certificate
	}
	if o.Key != nil {
		out.Key = *o.Key
	}
	if o.Method != nil {
		out.Method = *o.Method
	}

	return out
}

// DeepCopy returns a deep copy if the SparseIdentityModifier.
func (o *SparseIdentityModifier) DeepCopy() *SparseIdentityModifier {

	if o == nil {
		return nil
	}

	out := &SparseIdentityModifier{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseIdentityModifier.
func (o *SparseIdentityModifier) DeepCopyInto(out *SparseIdentityModifier) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseIdentityModifier: %s", err))
	}

	*out = *target.(*SparseIdentityModifier)
}

type mongoAttributesIdentityModifier struct {
	CA          string                      `bson:"ca,omitempty"`
	URL         string                      `bson:"url"`
	Certificate string                      `bson:"certificate"`
	Key         string                      `bson:"key"`
	Method      IdentityModifierMethodValue `bson:"method"`
}
type mongoAttributesSparseIdentityModifier struct {
	CA          *string                      `bson:"ca,omitempty"`
	URL         *string                      `bson:"url,omitempty"`
	Certificate *string                      `bson:"certificate,omitempty"`
	Key         *string                      `bson:"key,omitempty"`
	Method      *IdentityModifierMethodValue `bson:"method,omitempty"`
}
