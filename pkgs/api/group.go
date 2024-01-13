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

// GroupIdentity represents the Identity of the object.
var GroupIdentity = elemental.Identity{
	Name:     "group",
	Category: "groups",
	Package:  "a3s",
	Private:  false,
}

// GroupsList represents a list of Groups
type GroupsList []*Group

// Identity returns the identity of the objects in the list.
func (o GroupsList) Identity() elemental.Identity {

	return GroupIdentity
}

// Copy returns a pointer to a copy the GroupsList.
func (o GroupsList) Copy() elemental.Identifiables {

	out := append(GroupsList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the GroupsList.
func (o GroupsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(GroupsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*Group))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o GroupsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o GroupsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the GroupsList converted to SparseGroupsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o GroupsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseGroupsList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseGroup)
	}

	return out
}

// Version returns the version of the content.
func (o GroupsList) Version() int {

	return 1
}

// Group represents the model of a group
type Group struct {
	// ID is the identifier of the object.
	ID string `json:"ID" msgpack:"ID" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime time.Time `json:"createTime" msgpack:"createTime" bson:"createtime" mapstructure:"createTime,omitempty"`

	// Description of the group.
	Description string `json:"description" msgpack:"description" bson:"description" mapstructure:"description,omitempty"`

	// Set the group to be disabled.
	Disabled bool `json:"disabled" msgpack:"disabled" bson:"disabled" mapstructure:"disabled,omitempty"`

	// This is a set of all subject tags for matching in the DB.
	FlattenedSubject []string `json:"-" msgpack:"-" bson:"flattenedsubject" mapstructure:"-,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// Allows users to set a label to categorize group policies.
	Label string `json:"label" msgpack:"label" bson:"label" mapstructure:"label,omitempty"`

	// The name of the group.
	Name string `json:"name" msgpack:"name" bson:"name" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace" msgpack:"namespace" bson:"namespace" mapstructure:"namespace,omitempty"`

	// Opaque allows to store abitrary data into the group.
	Opaque map[string]any `json:"opaque,omitempty" msgpack:"opaque,omitempty" bson:"opaque,omitempty" mapstructure:"opaque,omitempty"`

	// Propagates the group to all of its children. This is always true.
	Propagate bool `json:"-" msgpack:"-" bson:"propagate" mapstructure:"-,omitempty"`

	// A tag expression that identifies the authorized user(s).
	Subject [][]string `json:"subject" msgpack:"subject" bson:"subject" mapstructure:"subject,omitempty"`

	// Last update date of the object.
	UpdateTime time.Time `json:"updateTime" msgpack:"updateTime" bson:"updatetime" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash int `json:"-" msgpack:"-" bson:"zhash" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone int `json:"-" msgpack:"-" bson:"zone" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewGroup returns a new *Group
func NewGroup() *Group {

	return &Group{
		ModelVersion:     1,
		FlattenedSubject: []string{},
		Propagate:        true,
		Subject:          [][]string{},
	}
}

// Identity returns the Identity of the object.
func (o *Group) Identity() elemental.Identity {

	return GroupIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *Group) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *Group) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Group) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesGroup{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.CreateTime = o.CreateTime
	s.Description = o.Description
	s.Disabled = o.Disabled
	s.FlattenedSubject = o.FlattenedSubject
	s.ImportHash = o.ImportHash
	s.ImportLabel = o.ImportLabel
	s.Label = o.Label
	s.Name = o.Name
	s.Namespace = o.Namespace
	s.Opaque = o.Opaque
	s.Propagate = o.Propagate
	s.Subject = o.Subject
	s.UpdateTime = o.UpdateTime
	s.ZHash = o.ZHash
	s.Zone = o.Zone

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Group) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesGroup{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.CreateTime = s.CreateTime
	o.Description = s.Description
	o.Disabled = s.Disabled
	o.FlattenedSubject = s.FlattenedSubject
	o.ImportHash = s.ImportHash
	o.ImportLabel = s.ImportLabel
	o.Label = s.Label
	o.Name = s.Name
	o.Namespace = s.Namespace
	o.Opaque = s.Opaque
	o.Propagate = s.Propagate
	o.Subject = s.Subject
	o.UpdateTime = s.UpdateTime
	o.ZHash = s.ZHash
	o.Zone = s.Zone

	return nil
}

// Version returns the hardcoded version of the model.
func (o *Group) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *Group) BleveType() string {

	return "group"
}

// DefaultOrder returns the list of default ordering fields.
func (o *Group) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *Group) Doc() string {

	return `TODO.`
}

func (o *Group) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetID returns the ID of the receiver.
func (o *Group) GetID() string {

	return o.ID
}

// SetID sets the property ID of the receiver using the given value.
func (o *Group) SetID(ID string) {

	o.ID = ID
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *Group) GetCreateTime() time.Time {

	return o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the given value.
func (o *Group) SetCreateTime(createTime time.Time) {

	o.CreateTime = createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *Group) GetImportHash() string {

	return o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the given value.
func (o *Group) SetImportHash(importHash string) {

	o.ImportHash = importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *Group) GetImportLabel() string {

	return o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the given value.
func (o *Group) SetImportLabel(importLabel string) {

	o.ImportLabel = importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *Group) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *Group) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *Group) GetPropagate() bool {

	return o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the given value.
func (o *Group) SetPropagate(propagate bool) {

	o.Propagate = propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *Group) GetUpdateTime() time.Time {

	return o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the given value.
func (o *Group) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *Group) GetZHash() int {

	return o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the given value.
func (o *Group) SetZHash(zHash int) {

	o.ZHash = zHash
}

// GetZone returns the Zone of the receiver.
func (o *Group) GetZone() int {

	return o.Zone
}

// SetZone sets the property Zone of the receiver using the given value.
func (o *Group) SetZone(zone int) {

	o.Zone = zone
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *Group) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseGroup{
			ID:               &o.ID,
			CreateTime:       &o.CreateTime,
			Description:      &o.Description,
			Disabled:         &o.Disabled,
			FlattenedSubject: &o.FlattenedSubject,
			ImportHash:       &o.ImportHash,
			ImportLabel:      &o.ImportLabel,
			Label:            &o.Label,
			Name:             &o.Name,
			Namespace:        &o.Namespace,
			Opaque:           &o.Opaque,
			Propagate:        &o.Propagate,
			Subject:          &o.Subject,
			UpdateTime:       &o.UpdateTime,
			ZHash:            &o.ZHash,
			Zone:             &o.Zone,
		}
	}

	sp := &SparseGroup{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "createTime":
			sp.CreateTime = &(o.CreateTime)
		case "description":
			sp.Description = &(o.Description)
		case "disabled":
			sp.Disabled = &(o.Disabled)
		case "flattenedSubject":
			sp.FlattenedSubject = &(o.FlattenedSubject)
		case "importHash":
			sp.ImportHash = &(o.ImportHash)
		case "importLabel":
			sp.ImportLabel = &(o.ImportLabel)
		case "label":
			sp.Label = &(o.Label)
		case "name":
			sp.Name = &(o.Name)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "opaque":
			sp.Opaque = &(o.Opaque)
		case "propagate":
			sp.Propagate = &(o.Propagate)
		case "subject":
			sp.Subject = &(o.Subject)
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

// Patch apply the non nil value of a *SparseGroup to the object.
func (o *Group) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseGroup)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.CreateTime != nil {
		o.CreateTime = *so.CreateTime
	}
	if so.Description != nil {
		o.Description = *so.Description
	}
	if so.Disabled != nil {
		o.Disabled = *so.Disabled
	}
	if so.FlattenedSubject != nil {
		o.FlattenedSubject = *so.FlattenedSubject
	}
	if so.ImportHash != nil {
		o.ImportHash = *so.ImportHash
	}
	if so.ImportLabel != nil {
		o.ImportLabel = *so.ImportLabel
	}
	if so.Label != nil {
		o.Label = *so.Label
	}
	if so.Name != nil {
		o.Name = *so.Name
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Opaque != nil {
		o.Opaque = *so.Opaque
	}
	if so.Propagate != nil {
		o.Propagate = *so.Propagate
	}
	if so.Subject != nil {
		o.Subject = *so.Subject
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

// DeepCopy returns a deep copy if the Group.
func (o *Group) DeepCopy() *Group {

	if o == nil {
		return nil
	}

	out := &Group{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Group.
func (o *Group) DeepCopyInto(out *Group) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Group: %s", err))
	}

	*out = *target.(*Group)
}

// Validate valides the current information stored into the structure.
func (o *Group) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("name", o.Name); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateAuthorizationSubject("subject", o.Subject); err != nil {
		errors = errors.Append(err)
	}
	if err := ValidateTagsExpression("subject", o.Subject); err != nil {
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
func (*Group) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := GroupAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return GroupLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Group) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return GroupAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Group) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "createTime":
		return o.CreateTime
	case "description":
		return o.Description
	case "disabled":
		return o.Disabled
	case "flattenedSubject":
		return o.FlattenedSubject
	case "importHash":
		return o.ImportHash
	case "importLabel":
		return o.ImportLabel
	case "label":
		return o.Label
	case "name":
		return o.Name
	case "namespace":
		return o.Namespace
	case "opaque":
		return o.Opaque
	case "propagate":
		return o.Propagate
	case "subject":
		return o.Subject
	case "updateTime":
		return o.UpdateTime
	case "zHash":
		return o.ZHash
	case "zone":
		return o.Zone
	}

	return nil
}

// GroupAttributesMap represents the map of attribute for Group.
var GroupAttributesMap = map[string]elemental.AttributeSpecification{
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
	"Description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the group.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"Disabled": {
		AllowedChoices: []string{},
		BSONFieldName:  "disabled",
		ConvertedName:  "Disabled",
		Description:    `Set the group to be disabled.`,
		Exposed:        true,
		Name:           "disabled",
		Stored:         true,
		Type:           "boolean",
	},
	"FlattenedSubject": {
		AllowedChoices: []string{},
		BSONFieldName:  "flattenedsubject",
		ConvertedName:  "FlattenedSubject",
		Description:    `This is a set of all subject tags for matching in the DB.`,
		Name:           "flattenedSubject",
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"ImportHash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "importhash",
		ConvertedName:  "ImportHash",
		CreationOnly:   true,
		Description:    `The hash of the structure used to compare with new import version.`,
		Exposed:        true,
		Getter:         true,
		Name:           "importHash",
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"ImportLabel": {
		AllowedChoices: []string{},
		BSONFieldName:  "importlabel",
		ConvertedName:  "ImportLabel",
		CreationOnly:   true,
		Description: `The user-defined import label that allows the system to group resources from the
same import operation.`,
		Exposed: true,
		Getter:  true,
		Name:    "importLabel",
		Setter:  true,
		Stored:  true,
		Type:    "string",
	},
	"Label": {
		AllowedChoices: []string{},
		BSONFieldName:  "label",
		ConvertedName:  "Label",
		Description:    `Allows users to set a label to categorize group policies.`,
		Exposed:        true,
		Name:           "label",
		Stored:         true,
		SubType:        "string",
		Type:           "string",
	},
	"Name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		Description:    `The name of the group.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
		Type:           "string",
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
	"Opaque": {
		AllowedChoices: []string{},
		BSONFieldName:  "opaque",
		ConvertedName:  "Opaque",
		Description:    `Opaque allows to store abitrary data into the group.`,
		Exposed:        true,
		Name:           "opaque",
		Stored:         true,
		SubType:        "map[string]any",
		Type:           "external",
	},
	"Propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the group to all of its children. This is always true.`,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"Subject": {
		AllowedChoices: []string{},
		BSONFieldName:  "subject",
		ConvertedName:  "Subject",
		Description:    `A tag expression that identifies the authorized user(s).`,
		Exposed:        true,
		Name:           "subject",
		Orderable:      true,
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
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

// GroupLowerCaseAttributesMap represents the map of attribute for Group.
var GroupLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
	"description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the group.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"disabled": {
		AllowedChoices: []string{},
		BSONFieldName:  "disabled",
		ConvertedName:  "Disabled",
		Description:    `Set the group to be disabled.`,
		Exposed:        true,
		Name:           "disabled",
		Stored:         true,
		Type:           "boolean",
	},
	"flattenedsubject": {
		AllowedChoices: []string{},
		BSONFieldName:  "flattenedsubject",
		ConvertedName:  "FlattenedSubject",
		Description:    `This is a set of all subject tags for matching in the DB.`,
		Name:           "flattenedSubject",
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"importhash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "importhash",
		ConvertedName:  "ImportHash",
		CreationOnly:   true,
		Description:    `The hash of the structure used to compare with new import version.`,
		Exposed:        true,
		Getter:         true,
		Name:           "importHash",
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"importlabel": {
		AllowedChoices: []string{},
		BSONFieldName:  "importlabel",
		ConvertedName:  "ImportLabel",
		CreationOnly:   true,
		Description: `The user-defined import label that allows the system to group resources from the
same import operation.`,
		Exposed: true,
		Getter:  true,
		Name:    "importLabel",
		Setter:  true,
		Stored:  true,
		Type:    "string",
	},
	"label": {
		AllowedChoices: []string{},
		BSONFieldName:  "label",
		ConvertedName:  "Label",
		Description:    `Allows users to set a label to categorize group policies.`,
		Exposed:        true,
		Name:           "label",
		Stored:         true,
		SubType:        "string",
		Type:           "string",
	},
	"name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		Description:    `The name of the group.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
		Type:           "string",
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
	"opaque": {
		AllowedChoices: []string{},
		BSONFieldName:  "opaque",
		ConvertedName:  "Opaque",
		Description:    `Opaque allows to store abitrary data into the group.`,
		Exposed:        true,
		Name:           "opaque",
		Stored:         true,
		SubType:        "map[string]any",
		Type:           "external",
	},
	"propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the group to all of its children. This is always true.`,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"subject": {
		AllowedChoices: []string{},
		BSONFieldName:  "subject",
		ConvertedName:  "Subject",
		Description:    `A tag expression that identifies the authorized user(s).`,
		Exposed:        true,
		Name:           "subject",
		Orderable:      true,
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
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

// SparseGroupsList represents a list of SparseGroups
type SparseGroupsList []*SparseGroup

// Identity returns the identity of the objects in the list.
func (o SparseGroupsList) Identity() elemental.Identity {

	return GroupIdentity
}

// Copy returns a pointer to a copy the SparseGroupsList.
func (o SparseGroupsList) Copy() elemental.Identifiables {

	copy := append(SparseGroupsList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseGroupsList.
func (o SparseGroupsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseGroupsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseGroup))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseGroupsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseGroupsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseGroupsList converted to GroupsList.
func (o SparseGroupsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseGroupsList) Version() int {

	return 1
}

// SparseGroup represents the sparse version of a group.
type SparseGroup struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime *time.Time `json:"createTime,omitempty" msgpack:"createTime,omitempty" bson:"createtime,omitempty" mapstructure:"createTime,omitempty"`

	// Description of the group.
	Description *string `json:"description,omitempty" msgpack:"description,omitempty" bson:"description,omitempty" mapstructure:"description,omitempty"`

	// Set the group to be disabled.
	Disabled *bool `json:"disabled,omitempty" msgpack:"disabled,omitempty" bson:"disabled,omitempty" mapstructure:"disabled,omitempty"`

	// This is a set of all subject tags for matching in the DB.
	FlattenedSubject *[]string `json:"-" msgpack:"-" bson:"flattenedsubject,omitempty" mapstructure:"-,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash *string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel *string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// Allows users to set a label to categorize group policies.
	Label *string `json:"label,omitempty" msgpack:"label,omitempty" bson:"label,omitempty" mapstructure:"label,omitempty"`

	// The name of the group.
	Name *string `json:"name,omitempty" msgpack:"name,omitempty" bson:"name,omitempty" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Opaque allows to store abitrary data into the group.
	Opaque *map[string]any `json:"opaque,omitempty" msgpack:"opaque,omitempty" bson:"opaque,omitempty" mapstructure:"opaque,omitempty"`

	// Propagates the group to all of its children. This is always true.
	Propagate *bool `json:"-" msgpack:"-" bson:"propagate,omitempty" mapstructure:"-,omitempty"`

	// A tag expression that identifies the authorized user(s).
	Subject *[][]string `json:"subject,omitempty" msgpack:"subject,omitempty" bson:"subject,omitempty" mapstructure:"subject,omitempty"`

	// Last update date of the object.
	UpdateTime *time.Time `json:"updateTime,omitempty" msgpack:"updateTime,omitempty" bson:"updatetime,omitempty" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash *int `json:"-" msgpack:"-" bson:"zhash,omitempty" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone *int `json:"-" msgpack:"-" bson:"zone,omitempty" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseGroup returns a new  SparseGroup.
func NewSparseGroup() *SparseGroup {
	return &SparseGroup{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseGroup) Identity() elemental.Identity {

	return GroupIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseGroup) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseGroup) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseGroup) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseGroup{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.CreateTime != nil {
		s.CreateTime = o.CreateTime
	}
	if o.Description != nil {
		s.Description = o.Description
	}
	if o.Disabled != nil {
		s.Disabled = o.Disabled
	}
	if o.FlattenedSubject != nil {
		s.FlattenedSubject = o.FlattenedSubject
	}
	if o.ImportHash != nil {
		s.ImportHash = o.ImportHash
	}
	if o.ImportLabel != nil {
		s.ImportLabel = o.ImportLabel
	}
	if o.Label != nil {
		s.Label = o.Label
	}
	if o.Name != nil {
		s.Name = o.Name
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.Opaque != nil {
		s.Opaque = o.Opaque
	}
	if o.Propagate != nil {
		s.Propagate = o.Propagate
	}
	if o.Subject != nil {
		s.Subject = o.Subject
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
func (o *SparseGroup) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseGroup{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.CreateTime != nil {
		o.CreateTime = s.CreateTime
	}
	if s.Description != nil {
		o.Description = s.Description
	}
	if s.Disabled != nil {
		o.Disabled = s.Disabled
	}
	if s.FlattenedSubject != nil {
		o.FlattenedSubject = s.FlattenedSubject
	}
	if s.ImportHash != nil {
		o.ImportHash = s.ImportHash
	}
	if s.ImportLabel != nil {
		o.ImportLabel = s.ImportLabel
	}
	if s.Label != nil {
		o.Label = s.Label
	}
	if s.Name != nil {
		o.Name = s.Name
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.Opaque != nil {
		o.Opaque = s.Opaque
	}
	if s.Propagate != nil {
		o.Propagate = s.Propagate
	}
	if s.Subject != nil {
		o.Subject = s.Subject
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
func (o *SparseGroup) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseGroup) ToPlain() elemental.PlainIdentifiable {

	out := NewGroup()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.CreateTime != nil {
		out.CreateTime = *o.CreateTime
	}
	if o.Description != nil {
		out.Description = *o.Description
	}
	if o.Disabled != nil {
		out.Disabled = *o.Disabled
	}
	if o.FlattenedSubject != nil {
		out.FlattenedSubject = *o.FlattenedSubject
	}
	if o.ImportHash != nil {
		out.ImportHash = *o.ImportHash
	}
	if o.ImportLabel != nil {
		out.ImportLabel = *o.ImportLabel
	}
	if o.Label != nil {
		out.Label = *o.Label
	}
	if o.Name != nil {
		out.Name = *o.Name
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Opaque != nil {
		out.Opaque = *o.Opaque
	}
	if o.Propagate != nil {
		out.Propagate = *o.Propagate
	}
	if o.Subject != nil {
		out.Subject = *o.Subject
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
func (o *SparseGroup) GetID() (out string) {

	if o.ID == nil {
		return
	}

	return *o.ID
}

// SetID sets the property ID of the receiver using the address of the given value.
func (o *SparseGroup) SetID(ID string) {

	o.ID = &ID
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *SparseGroup) GetCreateTime() (out time.Time) {

	if o.CreateTime == nil {
		return
	}

	return *o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the address of the given value.
func (o *SparseGroup) SetCreateTime(createTime time.Time) {

	o.CreateTime = &createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *SparseGroup) GetImportHash() (out string) {

	if o.ImportHash == nil {
		return
	}

	return *o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the address of the given value.
func (o *SparseGroup) SetImportHash(importHash string) {

	o.ImportHash = &importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *SparseGroup) GetImportLabel() (out string) {

	if o.ImportLabel == nil {
		return
	}

	return *o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the address of the given value.
func (o *SparseGroup) SetImportLabel(importLabel string) {

	o.ImportLabel = &importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseGroup) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseGroup) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *SparseGroup) GetPropagate() (out bool) {

	if o.Propagate == nil {
		return
	}

	return *o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the address of the given value.
func (o *SparseGroup) SetPropagate(propagate bool) {

	o.Propagate = &propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *SparseGroup) GetUpdateTime() (out time.Time) {

	if o.UpdateTime == nil {
		return
	}

	return *o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the address of the given value.
func (o *SparseGroup) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = &updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *SparseGroup) GetZHash() (out int) {

	if o.ZHash == nil {
		return
	}

	return *o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the address of the given value.
func (o *SparseGroup) SetZHash(zHash int) {

	o.ZHash = &zHash
}

// GetZone returns the Zone of the receiver.
func (o *SparseGroup) GetZone() (out int) {

	if o.Zone == nil {
		return
	}

	return *o.Zone
}

// SetZone sets the property Zone of the receiver using the address of the given value.
func (o *SparseGroup) SetZone(zone int) {

	o.Zone = &zone
}

// DeepCopy returns a deep copy if the SparseGroup.
func (o *SparseGroup) DeepCopy() *SparseGroup {

	if o == nil {
		return nil
	}

	out := &SparseGroup{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseGroup.
func (o *SparseGroup) DeepCopyInto(out *SparseGroup) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseGroup: %s", err))
	}

	*out = *target.(*SparseGroup)
}

type mongoAttributesGroup struct {
	ID               bson.ObjectId  `bson:"_id,omitempty"`
	CreateTime       time.Time      `bson:"createtime"`
	Description      string         `bson:"description"`
	Disabled         bool           `bson:"disabled"`
	FlattenedSubject []string       `bson:"flattenedsubject"`
	ImportHash       string         `bson:"importhash,omitempty"`
	ImportLabel      string         `bson:"importlabel,omitempty"`
	Label            string         `bson:"label"`
	Name             string         `bson:"name"`
	Namespace        string         `bson:"namespace"`
	Opaque           map[string]any `bson:"opaque,omitempty"`
	Propagate        bool           `bson:"propagate"`
	Subject          [][]string     `bson:"subject"`
	UpdateTime       time.Time      `bson:"updatetime"`
	ZHash            int            `bson:"zhash"`
	Zone             int            `bson:"zone"`
}
type mongoAttributesSparseGroup struct {
	ID               bson.ObjectId   `bson:"_id,omitempty"`
	CreateTime       *time.Time      `bson:"createtime,omitempty"`
	Description      *string         `bson:"description,omitempty"`
	Disabled         *bool           `bson:"disabled,omitempty"`
	FlattenedSubject *[]string       `bson:"flattenedsubject,omitempty"`
	ImportHash       *string         `bson:"importhash,omitempty"`
	ImportLabel      *string         `bson:"importlabel,omitempty"`
	Label            *string         `bson:"label,omitempty"`
	Name             *string         `bson:"name,omitempty"`
	Namespace        *string         `bson:"namespace,omitempty"`
	Opaque           *map[string]any `bson:"opaque,omitempty"`
	Propagate        *bool           `bson:"propagate,omitempty"`
	Subject          *[][]string     `bson:"subject,omitempty"`
	UpdateTime       *time.Time      `bson:"updatetime,omitempty"`
	ZHash            *int            `bson:"zhash,omitempty"`
	Zone             *int            `bson:"zone,omitempty"`
}
