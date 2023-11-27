// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"
	"time"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// RevocationIdentity represents the Identity of the object.
var RevocationIdentity = elemental.Identity{
	Name:     "revocation",
	Category: "revocations",
	Package:  "a3s",
	Private:  false,
}

// RevocationsList represents a list of Revocations
type RevocationsList []*Revocation

// Identity returns the identity of the objects in the list.
func (o RevocationsList) Identity() elemental.Identity {

	return RevocationIdentity
}

// Copy returns a pointer to a copy the RevocationsList.
func (o RevocationsList) Copy() elemental.Identifiables {

	out := append(RevocationsList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the RevocationsList.
func (o RevocationsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(RevocationsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*Revocation))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o RevocationsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o RevocationsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the RevocationsList converted to SparseRevocationsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o RevocationsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseRevocationsList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseRevocation)
	}

	return out
}

// Version returns the version of the content.
func (o RevocationsList) Version() int {

	return 1
}

// Revocation represents the model of a revocation
type Revocation struct {
	// ID is the identifier of the object.
	ID string `json:"ID" msgpack:"ID" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime time.Time `json:"createTime" msgpack:"createTime" bson:"createtime" mapstructure:"createTime,omitempty"`

	// The expiration date of the token.
	Expiration time.Time `json:"expiration" msgpack:"expiration" bson:"expiration" mapstructure:"expiration,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace" msgpack:"namespace" bson:"namespace" mapstructure:"namespace,omitempty"`

	// Propagates the api authorization to all of its children. This is always true.
	Propagate bool `json:"-" msgpack:"-" bson:"propagate" mapstructure:"-,omitempty"`

	// The ID of the revoked token.
	TokenID string `json:"tokenID" msgpack:"tokenID" bson:"tokenid" mapstructure:"tokenID,omitempty"`

	// Last update date of the object.
	UpdateTime time.Time `json:"updateTime" msgpack:"updateTime" bson:"updatetime" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash int `json:"-" msgpack:"-" bson:"zhash" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone int `json:"-" msgpack:"-" bson:"zone" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewRevocation returns a new *Revocation
func NewRevocation() *Revocation {

	return &Revocation{
		ModelVersion: 1,
		Propagate:    true,
	}
}

// Identity returns the Identity of the object.
func (o *Revocation) Identity() elemental.Identity {

	return RevocationIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *Revocation) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *Revocation) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Revocation) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesRevocation{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.CreateTime = o.CreateTime
	s.Expiration = o.Expiration
	s.Namespace = o.Namespace
	s.Propagate = o.Propagate
	s.TokenID = o.TokenID
	s.UpdateTime = o.UpdateTime
	s.ZHash = o.ZHash
	s.Zone = o.Zone

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Revocation) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesRevocation{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.CreateTime = s.CreateTime
	o.Expiration = s.Expiration
	o.Namespace = s.Namespace
	o.Propagate = s.Propagate
	o.TokenID = s.TokenID
	o.UpdateTime = s.UpdateTime
	o.ZHash = s.ZHash
	o.Zone = s.Zone

	return nil
}

// Version returns the hardcoded version of the model.
func (o *Revocation) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *Revocation) BleveType() string {

	return "revocation"
}

// DefaultOrder returns the list of default ordering fields.
func (o *Revocation) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *Revocation) Doc() string {

	return `A Revocation allows to mark a token as revoked based on its ID (jti).`
}

func (o *Revocation) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetID returns the ID of the receiver.
func (o *Revocation) GetID() string {

	return o.ID
}

// SetID sets the property ID of the receiver using the given value.
func (o *Revocation) SetID(ID string) {

	o.ID = ID
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *Revocation) GetCreateTime() time.Time {

	return o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the given value.
func (o *Revocation) SetCreateTime(createTime time.Time) {

	o.CreateTime = createTime
}

// GetNamespace returns the Namespace of the receiver.
func (o *Revocation) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *Revocation) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *Revocation) GetPropagate() bool {

	return o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the given value.
func (o *Revocation) SetPropagate(propagate bool) {

	o.Propagate = propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *Revocation) GetUpdateTime() time.Time {

	return o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the given value.
func (o *Revocation) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *Revocation) GetZHash() int {

	return o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the given value.
func (o *Revocation) SetZHash(zHash int) {

	o.ZHash = zHash
}

// GetZone returns the Zone of the receiver.
func (o *Revocation) GetZone() int {

	return o.Zone
}

// SetZone sets the property Zone of the receiver using the given value.
func (o *Revocation) SetZone(zone int) {

	o.Zone = zone
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *Revocation) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseRevocation{
			ID:         &o.ID,
			CreateTime: &o.CreateTime,
			Expiration: &o.Expiration,
			Namespace:  &o.Namespace,
			Propagate:  &o.Propagate,
			TokenID:    &o.TokenID,
			UpdateTime: &o.UpdateTime,
			ZHash:      &o.ZHash,
			Zone:       &o.Zone,
		}
	}

	sp := &SparseRevocation{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "createTime":
			sp.CreateTime = &(o.CreateTime)
		case "expiration":
			sp.Expiration = &(o.Expiration)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "propagate":
			sp.Propagate = &(o.Propagate)
		case "tokenID":
			sp.TokenID = &(o.TokenID)
		case "updateTime":
			sp.UpdateTime = &(o.UpdateTime)
		case "zHash":
			sp.ZHash = &(o.ZHash)
		case "zone":
			sp.Zone = &(o.Zone)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseRevocation to the object.
func (o *Revocation) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseRevocation)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.CreateTime != nil {
		o.CreateTime = *so.CreateTime
	}
	if so.Expiration != nil {
		o.Expiration = *so.Expiration
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Propagate != nil {
		o.Propagate = *so.Propagate
	}
	if so.TokenID != nil {
		o.TokenID = *so.TokenID
	}
	if so.UpdateTime != nil {
		o.UpdateTime = *so.UpdateTime
	}
	if so.ZHash != nil {
		o.ZHash = *so.ZHash
	}
	if so.Zone != nil {
		o.Zone = *so.Zone
	}
}

// DeepCopy returns a deep copy if the Revocation.
func (o *Revocation) DeepCopy() *Revocation {

	if o == nil {
		return nil
	}

	out := &Revocation{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Revocation.
func (o *Revocation) DeepCopyInto(out *Revocation) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Revocation: %s", err))
	}

	*out = *target.(*Revocation)
}

// Validate valides the current information stored into the structure.
func (o *Revocation) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("tokenID", o.TokenID); err != nil {
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
func (*Revocation) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := RevocationAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return RevocationLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Revocation) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return RevocationAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Revocation) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "createTime":
		return o.CreateTime
	case "expiration":
		return o.Expiration
	case "namespace":
		return o.Namespace
	case "propagate":
		return o.Propagate
	case "tokenID":
		return o.TokenID
	case "updateTime":
		return o.UpdateTime
	case "zHash":
		return o.ZHash
	case "zone":
		return o.Zone
	}

	return nil
}

// RevocationAttributesMap represents the map of attribute for Revocation.
var RevocationAttributesMap = map[string]elemental.AttributeSpecification{
	"ID": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "_id",
		ConvertedName:  "ID",
		Description:    `ID is the identifier of the object.`,
		Exposed:        true,
		Getter:         true,
		Identifier:     true,
		Name:           "ID",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"CreateTime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "createtime",
		ConvertedName:  "CreateTime",
		Description:    `Creation date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "createTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"Expiration": {
		AllowedChoices: []string{},
		BSONFieldName:  "expiration",
		ConvertedName:  "Expiration",
		Description:    `The expiration date of the token.`,
		Exposed:        true,
		Name:           "expiration",
		Stored:         true,
		Type:           "time",
	},
	"Namespace": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "namespace",
		ConvertedName:  "Namespace",
		Description:    `The namespace of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "namespace",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"Propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the api authorization to all of its children. This is always true.`,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"TokenID": {
		AllowedChoices: []string{},
		BSONFieldName:  "tokenid",
		ConvertedName:  "TokenID",
		Description:    `The ID of the revoked token.`,
		Exposed:        true,
		Name:           "tokenID",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"UpdateTime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "updatetime",
		ConvertedName:  "UpdateTime",
		Description:    `Last update date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "updateTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"ZHash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zhash",
		ConvertedName:  "ZHash",
		Description:    `Hash of the object used to shard the data.`,
		Getter:         true,
		Name:           "zHash",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "integer",
	},
	"Zone": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zone",
		ConvertedName:  "Zone",
		Description:    `Sharding zone.`,
		Getter:         true,
		Name:           "zone",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Transient:      true,
		Type:           "integer",
	},
}

// RevocationLowerCaseAttributesMap represents the map of attribute for Revocation.
var RevocationLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"id": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "_id",
		ConvertedName:  "ID",
		Description:    `ID is the identifier of the object.`,
		Exposed:        true,
		Getter:         true,
		Identifier:     true,
		Name:           "ID",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"createtime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "createtime",
		ConvertedName:  "CreateTime",
		Description:    `Creation date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "createTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"expiration": {
		AllowedChoices: []string{},
		BSONFieldName:  "expiration",
		ConvertedName:  "Expiration",
		Description:    `The expiration date of the token.`,
		Exposed:        true,
		Name:           "expiration",
		Stored:         true,
		Type:           "time",
	},
	"namespace": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "namespace",
		ConvertedName:  "Namespace",
		Description:    `The namespace of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "namespace",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the api authorization to all of its children. This is always true.`,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"tokenid": {
		AllowedChoices: []string{},
		BSONFieldName:  "tokenid",
		ConvertedName:  "TokenID",
		Description:    `The ID of the revoked token.`,
		Exposed:        true,
		Name:           "tokenID",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"updatetime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "updatetime",
		ConvertedName:  "UpdateTime",
		Description:    `Last update date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "updateTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"zhash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zhash",
		ConvertedName:  "ZHash",
		Description:    `Hash of the object used to shard the data.`,
		Getter:         true,
		Name:           "zHash",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "integer",
	},
	"zone": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zone",
		ConvertedName:  "Zone",
		Description:    `Sharding zone.`,
		Getter:         true,
		Name:           "zone",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Transient:      true,
		Type:           "integer",
	},
}

// SparseRevocationsList represents a list of SparseRevocations
type SparseRevocationsList []*SparseRevocation

// Identity returns the identity of the objects in the list.
func (o SparseRevocationsList) Identity() elemental.Identity {

	return RevocationIdentity
}

// Copy returns a pointer to a copy the SparseRevocationsList.
func (o SparseRevocationsList) Copy() elemental.Identifiables {

	copy := append(SparseRevocationsList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseRevocationsList.
func (o SparseRevocationsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseRevocationsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseRevocation))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseRevocationsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseRevocationsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseRevocationsList converted to RevocationsList.
func (o SparseRevocationsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseRevocationsList) Version() int {

	return 1
}

// SparseRevocation represents the sparse version of a revocation.
type SparseRevocation struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime *time.Time `json:"createTime,omitempty" msgpack:"createTime,omitempty" bson:"createtime,omitempty" mapstructure:"createTime,omitempty"`

	// The expiration date of the token.
	Expiration *time.Time `json:"expiration,omitempty" msgpack:"expiration,omitempty" bson:"expiration,omitempty" mapstructure:"expiration,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Propagates the api authorization to all of its children. This is always true.
	Propagate *bool `json:"-" msgpack:"-" bson:"propagate,omitempty" mapstructure:"-,omitempty"`

	// The ID of the revoked token.
	TokenID *string `json:"tokenID,omitempty" msgpack:"tokenID,omitempty" bson:"tokenid,omitempty" mapstructure:"tokenID,omitempty"`

	// Last update date of the object.
	UpdateTime *time.Time `json:"updateTime,omitempty" msgpack:"updateTime,omitempty" bson:"updatetime,omitempty" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash *int `json:"-" msgpack:"-" bson:"zhash,omitempty" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone *int `json:"-" msgpack:"-" bson:"zone,omitempty" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseRevocation returns a new  SparseRevocation.
func NewSparseRevocation() *SparseRevocation {
	return &SparseRevocation{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseRevocation) Identity() elemental.Identity {

	return RevocationIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseRevocation) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseRevocation) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseRevocation) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseRevocation{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.CreateTime != nil {
		s.CreateTime = o.CreateTime
	}
	if o.Expiration != nil {
		s.Expiration = o.Expiration
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.Propagate != nil {
		s.Propagate = o.Propagate
	}
	if o.TokenID != nil {
		s.TokenID = o.TokenID
	}
	if o.UpdateTime != nil {
		s.UpdateTime = o.UpdateTime
	}
	if o.ZHash != nil {
		s.ZHash = o.ZHash
	}
	if o.Zone != nil {
		s.Zone = o.Zone
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseRevocation) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseRevocation{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.CreateTime != nil {
		o.CreateTime = s.CreateTime
	}
	if s.Expiration != nil {
		o.Expiration = s.Expiration
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.Propagate != nil {
		o.Propagate = s.Propagate
	}
	if s.TokenID != nil {
		o.TokenID = s.TokenID
	}
	if s.UpdateTime != nil {
		o.UpdateTime = s.UpdateTime
	}
	if s.ZHash != nil {
		o.ZHash = s.ZHash
	}
	if s.Zone != nil {
		o.Zone = s.Zone
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseRevocation) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseRevocation) ToPlain() elemental.PlainIdentifiable {

	out := NewRevocation()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.CreateTime != nil {
		out.CreateTime = *o.CreateTime
	}
	if o.Expiration != nil {
		out.Expiration = *o.Expiration
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Propagate != nil {
		out.Propagate = *o.Propagate
	}
	if o.TokenID != nil {
		out.TokenID = *o.TokenID
	}
	if o.UpdateTime != nil {
		out.UpdateTime = *o.UpdateTime
	}
	if o.ZHash != nil {
		out.ZHash = *o.ZHash
	}
	if o.Zone != nil {
		out.Zone = *o.Zone
	}

	return out
}

// GetID returns the ID of the receiver.
func (o *SparseRevocation) GetID() (out string) {

	if o.ID == nil {
		return
	}

	return *o.ID
}

// SetID sets the property ID of the receiver using the address of the given value.
func (o *SparseRevocation) SetID(ID string) {

	o.ID = &ID
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *SparseRevocation) GetCreateTime() (out time.Time) {

	if o.CreateTime == nil {
		return
	}

	return *o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the address of the given value.
func (o *SparseRevocation) SetCreateTime(createTime time.Time) {

	o.CreateTime = &createTime
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseRevocation) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseRevocation) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *SparseRevocation) GetPropagate() (out bool) {

	if o.Propagate == nil {
		return
	}

	return *o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the address of the given value.
func (o *SparseRevocation) SetPropagate(propagate bool) {

	o.Propagate = &propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *SparseRevocation) GetUpdateTime() (out time.Time) {

	if o.UpdateTime == nil {
		return
	}

	return *o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the address of the given value.
func (o *SparseRevocation) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = &updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *SparseRevocation) GetZHash() (out int) {

	if o.ZHash == nil {
		return
	}

	return *o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the address of the given value.
func (o *SparseRevocation) SetZHash(zHash int) {

	o.ZHash = &zHash
}

// GetZone returns the Zone of the receiver.
func (o *SparseRevocation) GetZone() (out int) {

	if o.Zone == nil {
		return
	}

	return *o.Zone
}

// SetZone sets the property Zone of the receiver using the address of the given value.
func (o *SparseRevocation) SetZone(zone int) {

	o.Zone = &zone
}

// DeepCopy returns a deep copy if the SparseRevocation.
func (o *SparseRevocation) DeepCopy() *SparseRevocation {

	if o == nil {
		return nil
	}

	out := &SparseRevocation{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseRevocation.
func (o *SparseRevocation) DeepCopyInto(out *SparseRevocation) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseRevocation: %s", err))
	}

	*out = *target.(*SparseRevocation)
}

type mongoAttributesRevocation struct {
	ID         bson.ObjectId `bson:"_id,omitempty"`
	CreateTime time.Time     `bson:"createtime"`
	Expiration time.Time     `bson:"expiration"`
	Namespace  string        `bson:"namespace"`
	Propagate  bool          `bson:"propagate"`
	TokenID    string        `bson:"tokenid"`
	UpdateTime time.Time     `bson:"updatetime"`
	ZHash      int           `bson:"zhash"`
	Zone       int           `bson:"zone"`
}
type mongoAttributesSparseRevocation struct {
	ID         bson.ObjectId `bson:"_id,omitempty"`
	CreateTime *time.Time    `bson:"createtime,omitempty"`
	Expiration *time.Time    `bson:"expiration,omitempty"`
	Namespace  *string       `bson:"namespace,omitempty"`
	Propagate  *bool         `bson:"propagate,omitempty"`
	TokenID    *string       `bson:"tokenid,omitempty"`
	UpdateTime *time.Time    `bson:"updatetime,omitempty"`
	ZHash      *int          `bson:"zhash,omitempty"`
	Zone       *int          `bson:"zone,omitempty"`
}
