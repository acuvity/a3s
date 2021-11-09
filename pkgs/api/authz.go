package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.aporeto.io/elemental"
)

// AuthzIdentity represents the Identity of the object.
var AuthzIdentity = elemental.Identity{
	Name:     "authz",
	Category: "authz",
	Package:  "a3s",
	Private:  false,
}

// AuthzsList represents a list of Authzs
type AuthzsList []*Authz

// Identity returns the identity of the objects in the list.
func (o AuthzsList) Identity() elemental.Identity {

	return AuthzIdentity
}

// Copy returns a pointer to a copy the AuthzsList.
func (o AuthzsList) Copy() elemental.Identifiables {

	copy := append(AuthzsList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the AuthzsList.
func (o AuthzsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(AuthzsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*Authz))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o AuthzsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o AuthzsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the AuthzsList converted to SparseAuthzsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o AuthzsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseAuthzsList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseAuthz)
	}

	return out
}

// Version returns the version of the content.
func (o AuthzsList) Version() int {

	return 1
}

// Authz represents the model of a authz
type Authz struct {
	// The optional ID of the object to check permission for.
	ID string `json:"ID" msgpack:"ID" bson:"-" mapstructure:"ID,omitempty"`

	// IP of the client.
	IP string `json:"IP" msgpack:"IP" bson:"-" mapstructure:"IP,omitempty"`

	// The action to check permission for.
	Action string `json:"action" msgpack:"action" bson:"-" mapstructure:"action,omitempty"`

	// Audience that should be checked for.
	Audience string `json:"audience" msgpack:"audience" bson:"-" mapstructure:"audience,omitempty"`

	// The namespace where to check permission from.
	Namespace string `json:"namespace" msgpack:"namespace" bson:"-" mapstructure:"namespace,omitempty"`

	// The resource to check permission for.
	Resource string `json:"resource" msgpack:"resource" bson:"-" mapstructure:"resource,omitempty"`

	// The token to check.
	Token string `json:"token" msgpack:"token" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewAuthz returns a new *Authz
func NewAuthz() *Authz {

	return &Authz{
		ModelVersion: 1,
	}
}

// Identity returns the Identity of the object.
func (o *Authz) Identity() elemental.Identity {

	return AuthzIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *Authz) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *Authz) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Authz) GetBSON() (interface{}, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesAuthz{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Authz) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesAuthz{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *Authz) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *Authz) BleveType() string {

	return "authz"
}

// DefaultOrder returns the list of default ordering fields.
func (o *Authz) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *Authz) Doc() string {

	return `API to verify permissions.`
}

func (o *Authz) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *Authz) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseAuthz{
			ID:        &o.ID,
			IP:        &o.IP,
			Action:    &o.Action,
			Audience:  &o.Audience,
			Namespace: &o.Namespace,
			Resource:  &o.Resource,
			Token:     &o.Token,
		}
	}

	sp := &SparseAuthz{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "IP":
			sp.IP = &(o.IP)
		case "action":
			sp.Action = &(o.Action)
		case "audience":
			sp.Audience = &(o.Audience)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "resource":
			sp.Resource = &(o.Resource)
		case "token":
			sp.Token = &(o.Token)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseAuthz to the object.
func (o *Authz) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseAuthz)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.IP != nil {
		o.IP = *so.IP
	}
	if so.Action != nil {
		o.Action = *so.Action
	}
	if so.Audience != nil {
		o.Audience = *so.Audience
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Resource != nil {
		o.Resource = *so.Resource
	}
	if so.Token != nil {
		o.Token = *so.Token
	}
}

// DeepCopy returns a deep copy if the Authz.
func (o *Authz) DeepCopy() *Authz {

	if o == nil {
		return nil
	}

	out := &Authz{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Authz.
func (o *Authz) DeepCopyInto(out *Authz) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Authz: %s", err))
	}

	*out = *target.(*Authz)
}

// Validate valides the current information stored into the structure.
func (o *Authz) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("action", o.Action); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("namespace", o.Namespace); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("resource", o.Resource); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

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
func (*Authz) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := AuthzAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return AuthzLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Authz) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return AuthzAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Authz) ValueForAttribute(name string) interface{} {

	switch name {
	case "ID":
		return o.ID
	case "IP":
		return o.IP
	case "action":
		return o.Action
	case "audience":
		return o.Audience
	case "namespace":
		return o.Namespace
	case "resource":
		return o.Resource
	case "token":
		return o.Token
	}

	return nil
}

// AuthzAttributesMap represents the map of attribute for Authz.
var AuthzAttributesMap = map[string]elemental.AttributeSpecification{
	"ID": {
		AllowedChoices: []string{},
		ConvertedName:  "ID",
		Description:    `The optional ID of the object to check permission for.`,
		Exposed:        true,
		Name:           "ID",
		Type:           "string",
	},
	"IP": {
		AllowedChoices: []string{},
		ConvertedName:  "IP",
		Description:    `IP of the client.`,
		Exposed:        true,
		Name:           "IP",
		Type:           "string",
	},
	"Action": {
		AllowedChoices: []string{},
		ConvertedName:  "Action",
		Description:    `The action to check permission for.`,
		Exposed:        true,
		Name:           "action",
		Required:       true,
		Type:           "string",
	},
	"Audience": {
		AllowedChoices: []string{},
		ConvertedName:  "Audience",
		Description:    `Audience that should be checked for.`,
		Exposed:        true,
		Name:           "audience",
		Type:           "string",
	},
	"Namespace": {
		AllowedChoices: []string{},
		ConvertedName:  "Namespace",
		Description:    `The namespace where to check permission from.`,
		Exposed:        true,
		Name:           "namespace",
		Required:       true,
		Type:           "string",
	},
	"Resource": {
		AllowedChoices: []string{},
		ConvertedName:  "Resource",
		Description:    `The resource to check permission for.`,
		Exposed:        true,
		Name:           "resource",
		Required:       true,
		Type:           "string",
	},
	"Token": {
		AllowedChoices: []string{},
		ConvertedName:  "Token",
		Description:    `The token to check.`,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		SubType:        "string",
		Type:           "string",
	},
}

// AuthzLowerCaseAttributesMap represents the map of attribute for Authz.
var AuthzLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"id": {
		AllowedChoices: []string{},
		ConvertedName:  "ID",
		Description:    `The optional ID of the object to check permission for.`,
		Exposed:        true,
		Name:           "ID",
		Type:           "string",
	},
	"ip": {
		AllowedChoices: []string{},
		ConvertedName:  "IP",
		Description:    `IP of the client.`,
		Exposed:        true,
		Name:           "IP",
		Type:           "string",
	},
	"action": {
		AllowedChoices: []string{},
		ConvertedName:  "Action",
		Description:    `The action to check permission for.`,
		Exposed:        true,
		Name:           "action",
		Required:       true,
		Type:           "string",
	},
	"audience": {
		AllowedChoices: []string{},
		ConvertedName:  "Audience",
		Description:    `Audience that should be checked for.`,
		Exposed:        true,
		Name:           "audience",
		Type:           "string",
	},
	"namespace": {
		AllowedChoices: []string{},
		ConvertedName:  "Namespace",
		Description:    `The namespace where to check permission from.`,
		Exposed:        true,
		Name:           "namespace",
		Required:       true,
		Type:           "string",
	},
	"resource": {
		AllowedChoices: []string{},
		ConvertedName:  "Resource",
		Description:    `The resource to check permission for.`,
		Exposed:        true,
		Name:           "resource",
		Required:       true,
		Type:           "string",
	},
	"token": {
		AllowedChoices: []string{},
		ConvertedName:  "Token",
		Description:    `The token to check.`,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		SubType:        "string",
		Type:           "string",
	},
}

// SparseAuthzsList represents a list of SparseAuthzs
type SparseAuthzsList []*SparseAuthz

// Identity returns the identity of the objects in the list.
func (o SparseAuthzsList) Identity() elemental.Identity {

	return AuthzIdentity
}

// Copy returns a pointer to a copy the SparseAuthzsList.
func (o SparseAuthzsList) Copy() elemental.Identifiables {

	copy := append(SparseAuthzsList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseAuthzsList.
func (o SparseAuthzsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseAuthzsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseAuthz))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseAuthzsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseAuthzsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseAuthzsList converted to AuthzsList.
func (o SparseAuthzsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseAuthzsList) Version() int {

	return 1
}

// SparseAuthz represents the sparse version of a authz.
type SparseAuthz struct {
	// The optional ID of the object to check permission for.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// IP of the client.
	IP *string `json:"IP,omitempty" msgpack:"IP,omitempty" bson:"-" mapstructure:"IP,omitempty"`

	// The action to check permission for.
	Action *string `json:"action,omitempty" msgpack:"action,omitempty" bson:"-" mapstructure:"action,omitempty"`

	// Audience that should be checked for.
	Audience *string `json:"audience,omitempty" msgpack:"audience,omitempty" bson:"-" mapstructure:"audience,omitempty"`

	// The namespace where to check permission from.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"-" mapstructure:"namespace,omitempty"`

	// The resource to check permission for.
	Resource *string `json:"resource,omitempty" msgpack:"resource,omitempty" bson:"-" mapstructure:"resource,omitempty"`

	// The token to check.
	Token *string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseAuthz returns a new  SparseAuthz.
func NewSparseAuthz() *SparseAuthz {
	return &SparseAuthz{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseAuthz) Identity() elemental.Identity {

	return AuthzIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseAuthz) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseAuthz) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseAuthz) GetBSON() (interface{}, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseAuthz{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseAuthz) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseAuthz{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseAuthz) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseAuthz) ToPlain() elemental.PlainIdentifiable {

	out := NewAuthz()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.IP != nil {
		out.IP = *o.IP
	}
	if o.Action != nil {
		out.Action = *o.Action
	}
	if o.Audience != nil {
		out.Audience = *o.Audience
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Resource != nil {
		out.Resource = *o.Resource
	}
	if o.Token != nil {
		out.Token = *o.Token
	}

	return out
}

// DeepCopy returns a deep copy if the SparseAuthz.
func (o *SparseAuthz) DeepCopy() *SparseAuthz {

	if o == nil {
		return nil
	}

	out := &SparseAuthz{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseAuthz.
func (o *SparseAuthz) DeepCopyInto(out *SparseAuthz) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseAuthz: %s", err))
	}

	*out = *target.(*SparseAuthz)
}

type mongoAttributesAuthz struct {
}
type mongoAttributesSparseAuthz struct {
}
