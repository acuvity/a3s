package notification

import (
	"context"
	"log/slog"

	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// MakeNamespaceCleaner returns a generic namespace deletion job that will check for all
// existing identities and removed them.
func MakeNamespaceCleaner(ctx context.Context, m manipulate.Manipulator, manager elemental.ModelManager, ignored ...elemental.Identity) Handler {

	ignoreMap := make(map[elemental.Identity]struct{}, len(ignored))
	for _, v := range ignored {
		ignoreMap[v] = struct{}{}
	}

	return func(msg *Message) {

		if msg.Type != string(elemental.OperationDelete) {
			return
		}

		ns := msg.Data.(string)

		for _, i := range manager.AllIdentities() {

			if _, ok := ignoreMap[i]; ok {
				continue
			}

			mctx := manipulate.NewContext(
				ctx,
				manipulate.ContextOptionNamespace(ns),
				manipulate.ContextOptionRecursive(true),
			)

			if err := m.DeleteMany(mctx, i); err != nil {
				slog.Error("Unable to clean namespace", "ns", ns, err)
			}
		}
	}
}
