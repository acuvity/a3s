package importing

import "go.acuvity.ai/elemental"

// An Importable is the interface an object
// must satisfy in order to be importable.
type Importable interface {
	GetImportHash() string
	SetImportHash(string)
	GetImportLabel() string
	SetImportLabel(string)

	elemental.Namespaceable
	elemental.Identifiable
	elemental.AttributeSpecifiable
}
