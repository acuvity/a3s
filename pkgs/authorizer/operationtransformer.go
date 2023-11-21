package authorizer

import "go.acuvity.ai/elemental"

// A OperationTransformer is an interface that can transform the operation being evaluated.
type OperationTransformer interface {
	Transform(operation elemental.Operation) string
}
