package processors

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A LogoutProcessor is a bahamut processor for Logouts.
type LogoutProcessor struct {
	manipulator          manipulate.TransactionalManipulator
	pubsub               bahamut.PubSubClient
	cookieDomain         string
	cookieSameSitePolicy http.SameSite
}

// NewLogoutProcessor returns a new LogoutsProcessor.
func NewLogoutProcessor(
	manipulator manipulate.TransactionalManipulator,
	pubsub bahamut.PubSubClient,
	cookieSameSitePolicy http.SameSite,
	cookieDomain string,
) *LogoutProcessor {

	return &LogoutProcessor{
		manipulator:          manipulator,
		cookieDomain:         cookieDomain,
		cookieSameSitePolicy: cookieSameSitePolicy,
		pubsub:               pubsub,
	}
}

// ProcessCreate handles the creates requests for Logout.
func (p *LogoutProcessor) ProcessCreate(bctx bahamut.Context) error {

	tokenString := token.FromRequest(bctx.Request())
	idt, err := token.ParseUnverified(tokenString)
	if err != nil {
		return elemental.NewError(
			"Invalid Token",
			err.Error(),
			"a3s:authn",
			http.StatusBadRequest,
		)
	}

	var namespace string
	for _, c := range idt.Identity {
		if strings.HasPrefix(c, "@org=") {
			namespace = "/orgs/" + strings.TrimPrefix(c, "@org=")
			break
		}
	}

	if namespace == "" {
		namespace = "/orgs"
	}

	revocation := api.NewRevocation()
	revocation.CreateTime = time.Now()
	revocation.UpdateTime = revocation.CreateTime
	revocation.Expiration = idt.ExpiresAt.Time
	revocation.TokenID = idt.ID
	revocation.Propagate = true
	revocation.Namespace = namespace

	if err := p.manipulator.Create(
		manipulate.NewContext(
			bctx.Context(),
			manipulate.ContextOptionNamespace(namespace),
		),
		revocation,
	); err != nil {
		return fmt.Errorf("Unable to revoke token: %w", err)
	}

	slog.Info("Revoked token after logout", "ns", namespace, "jti", idt.ID)

	if err := p.notify(namespace); err != nil {
		return fmt.Errorf("unable to send revocation notification: %w", err)
	}

	c := &http.Cookie{
		Name:     "x-a3s-token",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(0, 0),
		SameSite: p.cookieSameSitePolicy,
		Path:     "/",
		Domain:   p.cookieDomain,
	}

	if err := c.Valid(); err != nil {
		slog.Error("Cookie about to be deleted is not valid", err)
	}

	bctx.AddOutputCookies(c)
	bctx.EnqueueEvents(elemental.NewEvent(elemental.EventCreate, revocation))

	return nil
}

func (p *LogoutProcessor) notify(ns string) error {
	return notification.Publish(
		p.pubsub,
		nscache.NotificationNamespaceChanges,
		&notification.Message{
			Data: ns,
		},
	)
}
