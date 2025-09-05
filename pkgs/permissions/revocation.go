package permissions

import (
	"context"
	"fmt"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func checkRevocation(ctx context.Context, m manipulate.Manipulator, namespace string, tokenID string, claims []string, iat time.Time) (bool, error) {

	var itags = make([]any, len(claims))
	for i, c := range claims {
		itags[i] = c
	}

	revs := api.SparseRevocationsList{}

	filters := []*elemental.Filter{}

	if tokenID != "" {
		filters = append(filters, elemental.NewFilterComposer().
			WithKey("tokenID").Equals(tokenID).
			Done(),
		)
	}

	if len(claims) > 0 {
		filters = append(filters, elemental.NewFilterComposer().
			WithKey("flattenedsubject").In(itags...).
			Done(),
		)
	}

	if len(filters) == 0 {
		return false, nil
	}

	if err := m.RetrieveMany(
		manipulate.NewContext(
			ctx,
			manipulate.ContextOptionNamespace(namespace),
			manipulate.ContextOptionPropagated(true),
			manipulate.ContextOptionFields([]string{"tokenID", "subject", "issuedBefore"}),
			manipulate.ContextOptionFilter(elemental.NewFilterComposer().Or(filters...).Done()),
		),
		&revs,
	); err != nil {
		return false, fmt.Errorf("unable to retrieve revocations: %w", err)
	}

	for _, rev := range revs {

		isRevoked := func() bool {
			return rev.IssuedBefore == nil || rev.IssuedBefore.IsZero() || iat.Before(*rev.IssuedBefore)
		}

		if rev.TokenID != nil && *rev.TokenID != "" && *rev.TokenID == tokenID {
			return isRevoked(), nil
		}

		if rev.Subject != nil && len(*rev.Subject) >= 0 {
			if Match(*rev.Subject, claims) {
				return isRevoked(), nil
			}
		}
	}

	return false, nil

}
