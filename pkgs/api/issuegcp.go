// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// IssueGCP represents the model of a issuegcp
type IssueGCP struct {
	// The required audience.
	Audience string `json:"audience" msgpack:"audience" bson:"-" mapstructure:"audience,omitempty"`

	// The original token.
	Token string `json:"token" msgpack:"token" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewIssueGCP returns a new *IssueGCP
func NewIssueGCP() *IssueGCP {

	return &IssueGCP{
		ModelVersion: 1,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *IssueGCP) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesIssueGCP{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *IssueGCP) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesIssueGCP{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *IssueGCP) BleveType() string {

	return "issuegcp"
}

// DeepCopy returns a deep copy if the IssueGCP.
func (o *IssueGCP) DeepCopy() *IssueGCP {

	if o == nil {
		return nil
	}

	out := &IssueGCP{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *IssueGCP.
func (o *IssueGCP) DeepCopyInto(out *IssueGCP) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy IssueGCP: %s", err))
	}

	*out = *target.(*IssueGCP)
}

// Validate valides the current information stored into the structure.
func (o *IssueGCP) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("token", o.Token); err != nil {
		requiredErrors = requiredErrors.Append(err)
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
func (*IssueGCP) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := IssueGCPAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return IssueGCPLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*IssueGCP) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return IssueGCPAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *IssueGCP) ValueForAttribute(name string) any {

	switch name {
	case "audience":
		return o.Audience
	case "token":
		return o.Token
	}

	return nil
}

// IssueGCPAttributesMap represents the map of attribute for IssueGCP.
var IssueGCPAttributesMap = map[string]elemental.AttributeSpecification{
	"Audience": {
		AllowedChoices: []string{},
		ConvertedName:  "Audience",
		Description:    `The required audience.`,
		Exposed:        true,
		Name:           "audience",
		Type:           "string",
	},
	"Token": {
		AllowedChoices: []string{},
		ConvertedName:  "Token",
		Description:    `The original token.`,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		Type:           "string",
	},
}

// IssueGCPLowerCaseAttributesMap represents the map of attribute for IssueGCP.
var IssueGCPLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"audience": {
		AllowedChoices: []string{},
		ConvertedName:  "Audience",
		Description:    `The required audience.`,
		Exposed:        true,
		Name:           "audience",
		Type:           "string",
	},
	"token": {
		AllowedChoices: []string{},
		ConvertedName:  "Token",
		Description:    `The original token.`,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		Type:           "string",
	},
}

type mongoAttributesIssueGCP struct {
}
