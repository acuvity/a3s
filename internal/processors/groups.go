package processors

import (
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A GroupsProcessors is a bahamut processor for Group.
type GroupsProcessors struct {
	manipulator manipulate.Manipulator
	pubsub      bahamut.PubSubClient
}

// NewGroupProcessor returns a new GroupsProcessors.
func NewGroupProcessor(
	manipulator manipulate.Manipulator,
	pubsub bahamut.PubSubClient,
) *GroupsProcessors {
	return &GroupsProcessors{
		manipulator: manipulator,
		pubsub:      pubsub,
	}
}

// ProcessCreate handles the creates requests for Groups.
func (p *GroupsProcessors) ProcessCreate(bctx bahamut.Context) error {
	return crud.Create(bctx, p.manipulator, bctx.InputData().(*api.Group),
		crud.OptionPreWriteHook(p.makePreHook(bctx)),
		crud.OptionPostWriteHook(p.makeNotify()),
	)
}

// ProcessRetrieveMany handles the retrieve many requests for Groups.
func (p *GroupsProcessors) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.GroupsList{})
}

// ProcessRetrieve handles the retrieve requests for Groups.
func (p *GroupsProcessors) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewGroup())
}

// ProcessUpdate handles the update requests for Groups.
func (p *GroupsProcessors) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.Group),
		crud.OptionPreWriteHook(p.makePreHook(bctx)),
		crud.OptionPostWriteHook(p.makeNotify()),
	)
}

// ProcessDelete handles the delete requests for Groups.
func (p *GroupsProcessors) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewGroup(),
		crud.OptionPostWriteHook(p.makeNotify()),
	)
}

// ProcessInfo handles the info request for Groups.
func (p *GroupsProcessors) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.GroupIdentity)
}

func (p *GroupsProcessors) makeNotify() crud.PostWriteHook {
	return func(obj elemental.Identifiable) {
		_ = notification.Publish(
			p.pubsub,
			nscache.NotificationNamespaceChanges,
			&notification.Message{
				Data: obj.(*api.Group).Namespace,
			},
		)
	}
}

func (p *GroupsProcessors) makePreHook(ctx bahamut.Context) crud.PreWriteHook {
	return func(obj elemental.Identifiable, original elemental.Identifiable) error {
		group := obj.(*api.Group)
		group.FlattenedSubject = flattenTags(group.Subject)
		return nil
	}
}
