package notification

import (
	"context"
	"fmt"
	"log/slog"

	"go.aporeto.io/bahamut"
)

// A Message represents the content of a notification.
type Message struct {
	Data any    `json:"d"`
	Type string `json:"t"`
}

// Handler is the type of function that can be Registered
// to handle a notification.
type Handler func(msg *Message)

// Subscribe registers a notification handler for the given topic.
func Subscribe(ctx context.Context, pubsub bahamut.PubSubClient, topic string, handler Handler) {

	pubs := make(chan *bahamut.Publication, 1024)
	errors := make(chan error, 16)
	d := pubsub.Subscribe(pubs, errors, topic)

	go func() {

		for {

			select {

			case pub := <-pubs:
				go func(p *bahamut.Publication) {
					msg := &Message{}
					if err := p.Decode(&msg); err != nil {
						slog.Error("Unable to decode notification message", err)
						return
					}
					handler(msg)
				}(pub)

			case err := <-errors:
				slog.Error("Received error from nats in notification", err)

			case <-ctx.Done():
				d()
				return
			}
		}
	}()
}

// Publish sends a notification message using the given pubsub server.
func Publish(pubsub bahamut.PubSubClient, topic string, msg *Message) error {

	pub := bahamut.NewPublication(topic)

	if err := pub.Encode(msg); err != nil {
		return fmt.Errorf("unable to encode notification publication: %w", err)
	}

	return pubsub.Publish(pub)
}
