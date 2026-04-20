package permissions

import (
	"context"
	"fmt"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

func checkRevocation(ctx context.Context, m manipulate.Manipulator, namespace string, tokenID string, claims []string, iat time.Time) (bool, time.Time, error) {

	var itags = make([]any, len(claims))
	for i, c := range claims {
		itags[i] = c
	}

	var ttl time.Time
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
		return false, ttl, nil
	}

	now := time.Now()

	f := elemental.NewFilterComposer().Or(filters...).Done()

	if err := m.RetrieveMany(
		manipulate.NewContext(
			ctx,
			manipulate.ContextOptionNamespace(namespace),
			manipulate.ContextOptionPropagated(true),
			manipulate.ContextOptionFields([]string{"tokenID", "subject", "issuedBefore", "activeAfter", "expiration"}),
			manipulate.ContextOptionFilter(f),
		),
		&revs,
	); err != nil {
		return false, ttl, fmt.Errorf("unable to retrieve revocations (claims: %s): %w", claims, err)
	}

	for _, rev := range revs {

		if rev.Expiration != nil && !rev.Expiration.IsZero() {

			if rev.Expiration.After(now) {
				if ttl.IsZero() || ttl.After(*rev.Expiration) {
					ttl = *rev.Expiration
				}
			}

			// if may have expired and mongo ttl did not kick in
			if rev.Expiration.Before(now) || rev.Expiration.Equal(now) {
				continue
			}
		}

		if rev.ActiveAfter != nil && !rev.ActiveAfter.IsZero() && rev.ActiveAfter.After(now) {
			if ttl.IsZero() || ttl.After(*rev.ActiveAfter) {
				ttl = *rev.ActiveAfter
			}

			continue
		}

		isRevoked := func() bool {
			return rev.IssuedBefore == nil || rev.IssuedBefore.IsZero() || iat.Before(*rev.IssuedBefore)
		}

		if rev.TokenID != nil && *rev.TokenID != "" && *rev.TokenID == tokenID {
			return isRevoked(), ttl, nil
		}

		if rev.Subject != nil && len(*rev.Subject) >= 0 {
			if Match(*rev.Subject, claims) {
				if isRevoked() {
					return true, ttl, nil
				}
			}
		}
	}

	return false, ttl, nil

}
