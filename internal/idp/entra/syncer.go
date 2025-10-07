package entra

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bsm/redislock"
	"github.com/globalsign/mgo/bson"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

var NotificationEntraSyncerUpdateSubscriptions = "entra.syncer.subscription.renew"

var (
	subscriptionLifetime = 4230 * time.Minute
	tickPeriod           = time.Hour
)

type Syncer struct {
	manager     *Manager
	manipulator manipulate.Manipulator
	hookURL     string
	pubsub      bahamut.PubSubClient
	locker      *redislock.Client
}

func NewSyncer(m manipulate.Manipulator, pubsub bahamut.PubSubClient, locker *redislock.Client, manager *Manager, hookURL string) *Syncer {

	return &Syncer{
		manager:     manager,
		manipulator: m,
		pubsub:      pubsub,
		hookURL:     hookURL,
		locker:      locker,
	}
}

func (s *Syncer) Start(ctx context.Context) {

	go func() {

		ticker := time.NewTicker(tickPeriod)
		defer ticker.Stop()

		tick := func() {

			octx, ocancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ocancel()

			lock, err := s.locker.Obtain(octx, "a3s:entra:syncer:batch", 30*time.Minute, &redislock.Options{RetryStrategy: redislock.NoRetry()})
			if err != nil {
				if !errors.Is(err, redislock.ErrNotObtained) {
					slog.Info("Unable to acquire lock 'a3s:entra:syncer:batch'", err)
				}
				return
			}

			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer func() {
				if err := lock.Release(rctx); err != nil {
					slog.Error("Unable to release lock for 'a3s:entra:syncer:single'", err)
				}
				rcancel()
			}()

			sources, err := s.findRelevantMTLSSources(ctx)
			if err != nil {
				slog.Error("Unable to find relevant MTLS Sources", err)
				return
			}

			if len(sources) == 0 {
				slog.Debug("No MTLS sources nearing subscription expiration.")
				return
			}

			elapsed := time.Now()
			var created, updated int
			for _, src := range sources {
				c, u, err := s.syncSource(ctx, src)
				if err != nil {
					slog.Error("Unable to sync subscription", "srcid", src.ID, "srcname", src.Name, "namespace", src.Namespace, err)
				} else {
					created += c
					updated += u
				}
			}

			slog.Info("Updated Entra subscriptions for MTLSSources", "created", created, "updated", updated, "sources", len(sources), "took", time.Since(elapsed))
		}

		tick()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tick()
			}
		}
	}()

	go func() {

		notification.Subscribe(ctx, s.pubsub, NotificationEntraSyncerUpdateSubscriptions, func(msg *notification.Message) {

			octx, ocancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ocancel()

			lock, err := s.locker.Obtain(octx, "a3s:entra:syncer:single", 30*time.Second, &redislock.Options{RetryStrategy: redislock.NoRetry()})
			if err != nil {
				if !errors.Is(err, redislock.ErrNotObtained) {
					slog.Info("Unable to lock 'a3s:entra:syncer:single'", err)
				}
				return
			}

			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer func() {
				if err := lock.Release(rctx); err != nil {
					slog.Error("Unable to release lock for 'a3s:entra:syncer:single'", err)
				}
				rcancel()
			}()

			bdata, err := base64.StdEncoding.DecodeString(msg.Data.(string))
			if err != nil {
				slog.Error("Unable to decode notification message b64 data", err)
				return
			}

			src := api.NewMTLSSource()
			if err := bson.Unmarshal(bdata, src); err != nil {
				slog.Error("Unable to decode notification message bson data", err)
				return
			}

			if msg.Type == string(elemental.OperationDelete) ||
				src.EntraApplicationCredentials == nil ||
				!src.EntraApplicationCredentials.GraphEventsEnabled {
				slog.Debug("Unsubscribing MTLSSource from Entra notifications", "srcid", src.ID, "srcns", src.Namespace, "op", msg.Type)
				for k := range src.EntraApplicationCredentials.GraphSubscriptionIDs {
					if err := s.manager.Unsubscribe(ctx, src.EntraApplicationCredentials, k); err != nil {
						slog.Error("Unable to unsubscribe", "srcid", src.ID, "op", msg.Type, err)
					}
				}
				return
			}

			slog.Debug("Subscribing MTLSSource to Entra notifications", "srcid", src.ID, "srcns", src.Namespace, "op", msg.Type)
			if _, _, err := s.syncSource(ctx, src); err != nil {
				slog.Error("Unable to sync MTLSSource with entra", "srcid", src.ID, "srcns", src.Namespace, "op", msg.Type, err)
			}

		})
	}()
}

func (s *Syncer) syncSource(ctx context.Context, src *api.MTLSSource) (created int, updated int, err error) {

	if src.EntraApplicationCredentials.GraphSubscriptionIDs == nil {
		src.EntraApplicationCredentials.GraphSubscriptionIDs = map[string]string{}
	}

	gsid := src.EntraApplicationCredentials.GraphSubscriptionIDs["groups"]
	usid := src.EntraApplicationCredentials.GraphSubscriptionIDs["users"]

	// Groups subscriptions
	if gsid != "" {

		// If we have a stored group sub id, we renew it
		slog.Debug("Renewing /groups subscription for source", "srcid", src.ID, "srcname", src.Name, "namespace", src.Namespace, "sub", gsid)
		sub, err := s.manager.RenewSubscription(ctx, src.EntraApplicationCredentials, gsid, subscriptionLifetime)
		if err != nil {
			slog.Debug("Unable to renew subscription to /groups. Trying to subscribe", "source-id", src.ID, "source-name", src.Name, "namespace", src.Namespace, err)
			gsid = ""
		}

		if sub == nil {
			slog.Debug("Unable to renew subscription to /groups. Trying to subscribe", "source-id", src.ID, "source-name", src.Name, "namespace", src.Namespace, "err", "not-found")
			gsid = ""
		} else {
			updated++
		}
	}

	if gsid == "" {

		// If at that point we have no group sub id, we create a new sub
		slog.Debug("Creating new /groups subscription for source", "srcid", src.ID, "srcname", src.Name, "namespace", src.Namespace)
		sub, err := s.manager.Subscribe(ctx, src.EntraApplicationCredentials, "/groups", s.hookURL, "", subscriptionLifetime, "updated,deleted")
		if err != nil {
			return created, updated, fmt.Errorf("unable to subscribe to /groups: %w", err)
		}

		src.EntraApplicationCredentials.GraphSubscriptionIDs["groups"] = sub.ID
		created++
	}

	// Users subscriptions
	if usid != "" {

		// If we have a stored user sub id, we renew it
		slog.Debug("Renewing /users subscription for source", "srcid", src.ID, "srcname", src.Name, "namespace", src.Namespace, "sub", usid)
		sub, err := s.manager.RenewSubscription(ctx, src.EntraApplicationCredentials, gsid, subscriptionLifetime)
		if err != nil {
			slog.Debug("Unable to renew subscription to /users. Trying to subscribe", "source-id", src.ID, "source-name", src.Name, "namespace", src.Namespace, err)
			usid = ""
		}

		if sub == nil {
			slog.Debug("Unable to renew subscription to /users. Trying to subscribe", "source-id", src.ID, "source-name", src.Name, "namespace", src.Namespace, "err", "not-found")
			usid = ""
		} else {
			updated++
		}
	}

	if usid == "" {

		// If at that point we have no users sub id, we create a new sub
		slog.Debug("Creating new /users subscription for source", "source-id", src.ID, "source-name", src.Name, "namespace", src.Namespace)
		sub, err := s.manager.Subscribe(ctx, src.EntraApplicationCredentials, "/users", s.hookURL, "", subscriptionLifetime, "updated,deleted")
		if err != nil {
			return created, updated, fmt.Errorf("unable to subscribe to /users: %w", err)
		}

		src.EntraApplicationCredentials.GraphSubscriptionIDs["users"] = sub.ID
		created++
	}

	// If we have updated the sub, we update it in the mtls source internal data
	if created > 0 || updated > 0 {

		// We also update the expiration time.
		src.EntraApplicationCredentials.GraphSubscriptionExpiration = time.Now().Add(subscriptionLifetime)

		slog.Debug("Updating MTLSSource with new subscriptions ids", "subs", src.EntraApplicationCredentials.GraphSubscriptionIDs)
		if err := s.manipulator.Update(manipulate.NewContext(ctx), src); err != nil {
			return created, updated, fmt.Errorf("unable to update subscriptions ids in mtls source: %w", err)
		}
	}

	return created, updated, nil
}

func (s *Syncer) findRelevantMTLSSources(ctx context.Context) (api.MTLSSourcesList, error) {

	maxExp := time.Now().Add((subscriptionLifetime / 3) * 2)

	mctx := manipulate.NewContext(
		ctx,
		manipulate.ContextOptionFilter(
			elemental.NewFilterComposer().
				WithKey("entraapplicationcredentials.grapheventsenabled").Equals(true).
				And(
					elemental.NewFilterComposer().Or(
						elemental.NewFilterComposer().WithKey("entraapplicationcredentials.graphsubscriptionexpiration").LesserOrEqualThan(maxExp).Done(),
						elemental.NewFilterComposer().WithKey("entraapplicationcredentials.graphsubscriptionexpiration").Equals(time.Time{}).Done(),
						elemental.NewFilterComposer().WithKey("entraapplicationcredentials.graphsubscriptionexpiration").NotExists().Done(),
					).
						Done(),
				).
				Done(),
		),
	)

	mtlssources := api.MTLSSourcesList{}
	if err := s.manipulator.RetrieveMany(mctx, &mtlssources); err != nil {
		return nil, fmt.Errorf("unable to find relevant entra graph enabled MTLSSources: %w", err)
	}

	return mtlssources, nil
}
