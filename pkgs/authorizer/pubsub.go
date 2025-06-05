package authorizer

import (
	"context"
	"sync"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/manipulate"
)

type eventData struct {
	Namespace string `json:"namespace" msgpack:"namespace"`
	Name      string `json:"name" msgpack:"name"`
}

type subscription struct {
	errors chan error
	pubs   chan *bahamut.Publication
	topic  string
}

// webSocketPubSub is a naive bahamut.PubSubClient internal implementation
// that is backed by a manipulate.Subscriber. This is used to
// make the Authorizer working when used by third party clients that
// won't have access to the internal NATS notification topic.
// It basically acts a shim layer that translates classic elemental.Events
// into the relevant notification.Message used by the authorizer internal
// namespace cache.
type webSocketPubSub struct {
	subscriber manipulate.Subscriber
	subs       []subscription
	sublock    sync.RWMutex
}

func (w *webSocketPubSub) Connect(context.Context) error {

	sendErr := func(err error) {
		for _, sub := range w.subs {
			select {
			case sub.errors <- err:
			default:
			}
		}
	}

	sendPub := func(pub *bahamut.Publication) {
		for _, sub := range w.subs {
			select {
			case sub.pubs <- pub:
			default:
			}
		}
	}

	go func() {

		for {
			select {

			case evt := <-w.subscriber.Events():

				// We decode the event in a generic container structure.
				d := &eventData{}
				if err := evt.Decode(d); err != nil {
					w.sublock.RLock()
					sendErr(err)
					w.sublock.RUnlock()
					continue
				}

				// We prepare a notification Message that the authorizer
				// nscache will understand.
				msg := notification.Message{
					Type: nscache.NotificationNamespaceChanges,
				}

				// We populate the namespace name based on the
				// event identity.
				switch evt.Identity {
				case api.NamespaceIdentity.Name:
					msg.Data = d.Name
				case api.AuthorizationIdentity.Name:
					msg.Data = d.Namespace
				case api.RevocationIdentity.Name:
					msg.Data = d.Namespace
				case api.GroupIdentity.Name:
					msg.Data = d.Namespace
				}

				// Then we create a publication and wrap the msg inside.
				w.sublock.RLock()
				for _, sub := range w.subs {
					p := bahamut.NewPublication(sub.topic)
					if err := p.Encode(msg); err != nil {
						sendErr(err)
						continue
					}
					sendPub(p)
				}
				w.sublock.RUnlock()

			case st := <-w.subscriber.Status():
				if st == manipulate.SubscriberStatusFinalDisconnection {
					return
				}

			case err := <-w.subscriber.Errors():
				sendErr(err)
			}
		}
	}()

	return nil
}

func (w *webSocketPubSub) Subscribe(pubs chan *bahamut.Publication, errors chan error, topic string, opts ...bahamut.PubSubOptSubscribe) func() {

	w.sublock.Lock()
	w.subs = append(
		w.subs,
		subscription{
			pubs:   pubs,
			errors: errors,
			topic:  topic,
		},
	)
	w.sublock.Unlock()

	return func() { w.subscriber.Status() <- manipulate.SubscriberStatusFinalDisconnection }
}

// not implemented. These are just here to satisfy the bahamut.PubSubClient interface.
func (w *webSocketPubSub) Disconnect() error { return nil }
func (w *webSocketPubSub) Publish(*bahamut.Publication, ...bahamut.PubSubOptPublish) error {
	return nil
}
