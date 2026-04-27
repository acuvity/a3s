package processors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bsm/redislock"
	"github.com/cespare/xxhash/v2"
	"github.com/karlseguin/ccache/v3"
	"go.acuvity.ai/a3s/internal/idp/entra"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A EntraEventsProcessor is a bahamut processor for EntraEvents.
type EntraEventsProcessor struct {
	manipulator  manipulate.TransactionalManipulator
	locker       *redislock.Client
	entraManager *entra.Manager
	quiteTime    time.Duration
	gracePeriod  time.Duration
	srccache     *ccache.Cache[*api.MTLSSource]
}

// NewEntraEventsProcessor returns a new EntraEventsProcessor.
func NewEntraEventsProcessor(manipulator manipulate.TransactionalManipulator, entraManager *entra.Manager, locker *redislock.Client, quietTime time.Duration, gracePeriod time.Duration) *EntraEventsProcessor {

	return &EntraEventsProcessor{
		manipulator:  manipulator,
		locker:       locker,
		entraManager: entraManager,
		quiteTime:    quietTime,
		gracePeriod:  gracePeriod,
		srccache:     ccache.New(ccache.Configure[*api.MTLSSource]().MaxSize(1024)),
	}
}

// ProcessCreate handles the creates requests for EntraEvents.
func (p *EntraEventsProcessor) ProcessCreate(bctx bahamut.Context) error {

	evt := bctx.InputData().(*api.EntraEvent)

	if evt.Payload == "" {
		return elemental.NewError("Bad Request", "Received an EntraEvent with an empty payload", "a3s", http.StatusBadRequest)
	}

	payload := &entraPayload{}
	if err := elemental.Decode(elemental.EncodingTypeJSON, []byte(evt.Payload), payload); err != nil {
		return elemental.NewError("Bad Request", fmt.Sprintf("Unable to decode entra event payload: %s", err), "a3s", http.StatusBadRequest)
	}

	for _, v := range payload.Value {

		octx, ocancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ocancel()

		log := slog.With("tenantid", v.TenantID, "subid", v.SubscriptionID, "change", v.ChangeType, "resource", v.Resource)

		key := fmt.Sprintf("a3s:entra:events:%s:%s:%s:%s:%s", v.ClientState, v.ChangeType, v.Resource, v.SubscriptionID, v.TenantID)
		_, err := p.locker.Obtain(octx, key, p.quiteTime, &redislock.Options{RetryStrategy: redislock.NoRetry()})
		if err != nil {
			if errors.Is(err, redislock.ErrNotObtained) {
				return nil
			} else {
				log.Error("Unable to acquire lock '%s'", key, err)
				return err
			}
		}

		// We do not release the lock. We want it to stay in place until it expires
		// so we don't manage the BS flood of duplicated events from these microsoft
		// morons.

		log.Debug("Received Entra notification", "payload", evt.Payload)

		f := elemental.NewFilterComposer().
			WithKey("entraapplicationcredentials.grapheventsenabled").Equals(true).
			WithKey("entraapplicationcredentials.grapheventsecret").Equals(v.ClientState).
			WithKey("entraapplicationcredentials.clienttenantid").Equals(v.TenantID).
			Done()

		ckey := fmt.Sprintf("%x", xxhash.Sum64String(f.String()))

		var src *api.MTLSSource
		if item := p.srccache.Get(ckey); item != nil && !item.Expired() {
			src = item.Value()
			log.Debug("Handling Entra notification", "src-cached", true)
		} else {

			mctx := manipulate.NewContext(
				bctx.Context(),
				manipulate.ContextOptionRecursive(true),
				manipulate.ContextOptionFilter(f),
			)

			sources := api.MTLSSourcesList{}
			if err := p.manipulator.RetrieveMany(mctx, &sources); err != nil {
				log.Warn("Unable to retrieve mtlssource", err)
				continue
			}

			switch len(sources) {
			case 1:
			case 0:
				log.Warn("No MTLS sources found for the given clientState", "expiration", v.SubscriptionExpirationDateTime)
				continue
			default:
				log.Error("Multiple MTLS sources found for the given clientState")
				continue
			}

			log.Debug("Handling Entra notification", "src-cached", false)

			src = sources[0]
		}

		if strings.HasPrefix(v.Resource, "Groups/") && v.ResourceData.MembersDelta != nil {
			for _, member := range *v.ResourceData.MembersDelta {
				p.invalidateTokensMacthing(bctx.Context(), log, src, []string{fmt.Sprintf("nameid=%s", member.ID)})
			}
			return nil
		}

		if strings.HasPrefix(v.Resource, "Groups/") && v.ResourceData.MembersDelta == nil {
			p.invalidateTokensMacthing(bctx.Context(), log, src, []string{fmt.Sprintf("group:id=%s", v.ResourceData.ID)})
			return nil
		}

		if strings.HasPrefix(v.Resource, "Users/") {
			p.invalidateTokensMacthing(bctx.Context(), log, src, []string{fmt.Sprintf("nameid=%s", v.ResourceData.ID)})
			return nil
		}
	}

	return nil
}

func (p *EntraEventsProcessor) invalidateTokensMacthing(ctx context.Context, logger *slog.Logger, src *api.MTLSSource, claims []string) {

	fclaims := append([]string{
		"@source:type=mtls",
		fmt.Sprintf("@source:name=%s", src.Name),
		fmt.Sprintf("@source:namespace=%s", src.Namespace),
	}, claims...)

	// We disable this for now, as it creates quite a lot of scaling issue.
	_ = ctx // hush linter for now

	// revoke := idp.MakeEventTriggeredRevocation(fclaims, src.Namespace, p.gracePeriod)

	// if err := p.manipulator.Create(manipulate.NewContext(ctx), revoke); err != nil {
	// 	logger.Error("Unable to revoke entra tokens", "namespace", src.Namespace, "revoked", fclaims, err)
	// 	return
	// }

	logger.Info("EntraEvent triggered tokens revocation", "namespace", src.Namespace, "revoked", fclaims, "DRYRUN", true)
}

type entraPayload struct {
	Value []struct {
		ChangeType                     string    `json:"changeType"`
		ClientState                    string    `json:"clientState"`
		Resource                       string    `json:"resource"`
		SubscriptionExpirationDateTime time.Time `json:"subscriptionExpirationDateTime"`
		SubscriptionID                 string    `json:"subscriptionId"`
		TenantID                       string    `json:"tenantId"`
		ResourceData                   struct {
			DataType       string `json:"@odata.type"`
			DataID         string `json:"@odata.id"`
			ID             string `json:"id"`
			OrganizationID string `json:"organizationID"`
			MembersDelta   *[]struct {
				ID      string `json:"id"`
				Removed string `json:"@removed"`
			} `json:"members@delta"`
		} `json:"resourceData"`
	} `json:"value"`
}
