package namespace

import (
	"regexp"

	"go.acuvity.ai/elemental"
)

// NewSubtreeFilter matches a namespace and its slash-delimited descendants,
// treating namespace names literally rather than as regular expressions.
// An empty namespace, like "/", selects all absolute namespaces.
func NewSubtreeFilter(namespace string) *elemental.Filter {
	if namespace == "" || namespace == "/" {
		return elemental.NewFilterComposer().WithKey("namespace").Matches("^/").Done()
	}

	return elemental.NewFilterComposer().Or(
		elemental.NewFilterComposer().WithKey("namespace").Equals(namespace).Done(),
		elemental.NewFilterComposer().WithKey("namespace").Matches("^"+regexp.QuoteMeta(namespace)+"/").Done(),
	).Done()
}
