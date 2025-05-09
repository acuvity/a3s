package authorizer

import (
	"context"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniphttp"
)

type remoteAuthorizer struct {
	Authorizer
}

// NewRemote returns a ready to use bahamut.Authorizer that can be used over the API.
// This is meant to be use by external bahamut service.
// Updates of the namespace/authorization state comes from the websocket.
func NewRemote(ctx context.Context, m manipulate.Manipulator, r permissions.Retriever, options ...Option) Authorizer {

	subscriber := maniphttp.NewSubscriber(
		m,
		maniphttp.SubscriberOptionRecursive(true),
		maniphttp.SubscriberOptionNamespace(maniphttp.ExtractNamespace(m)),
		maniphttp.SubscriberSendCredentialsAsCookie("x-a3s-token"),
	)

	pcfg := elemental.NewPushConfig()
	pcfg.FilterIdentity(api.NamespaceIdentity.Name)
	pcfg.FilterIdentity(api.AuthorizationIdentity.Name)
	pcfg.FilterIdentity(api.RevocationIdentity.Name)

	subscriber.Start(ctx, pcfg)
	wsps := &webSocketPubSub{subscriber: subscriber}
	_ = wsps.Connect(ctx)

	return &remoteAuthorizer{
		Authorizer: New(ctx, r, wsps, options...),
	}
}
