package permissions

import (
	"context"
	"fmt"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func checkRevocation(ctx context.Context, m manipulate.Manipulator, namespace string, tokenID string, claims []string) (bool, error) {

	var itags = make([]any, len(claims))
	for i, c := range claims {
		itags[i] = c
	}

	revs := api.SparseRevocationsList{}

	if err := m.RetrieveMany(
		manipulate.NewContext(
			ctx,
			manipulate.ContextOptionNamespace(namespace),
			manipulate.ContextOptionPropagated(true),
			manipulate.ContextOptionFields([]string{"tokenID", "subject"}),
			manipulate.ContextOptionFilter(
				elemental.NewFilterComposer().Or(
					elemental.NewFilterComposer().
						WithKey("tokenID").Equals(tokenID).
						Done(),
					elemental.NewFilterComposer().
						WithKey("flattenedsubject").In(itags...).
						Done(),
				).Done(),
			),
		),
		&revs,
	); err != nil {
		return false, fmt.Errorf("unable to retrieve revocations: %w", err)
	}

	for _, rev := range revs {
		if rev.TokenID != nil && *rev.TokenID == tokenID {
			return true, nil
		}

		if rev.Subject != nil {
			if Match(*rev.Subject, claims) {
				return true, nil
			}
		}
	}

	return false, nil

}
