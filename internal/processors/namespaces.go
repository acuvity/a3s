package processors

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/crud"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/a3s/pkgs/nscache"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// A NamespacesProcessor is a bahamut processor for Namespaces.
type NamespacesProcessor struct {
	manipulator manipulate.Manipulator
	pubsub      bahamut.PubSubClient
}

// NewNamespacesProcessor returns a new NamespacesProcessor.
func NewNamespacesProcessor(manipulator manipulate.Manipulator, pubsub bahamut.PubSubClient) *NamespacesProcessor {
	return &NamespacesProcessor{
		manipulator: manipulator,
		pubsub:      pubsub,
	}
}

// ProcessCreate handles the creates requests for Namespaces.
func (p *NamespacesProcessor) ProcessCreate(bctx bahamut.Context) error {

	ns := bctx.InputData().(*api.Namespace)
	rns := bctx.Request().Namespace

	name, err := alignNamespacName(ns.Name, rns)
	if err != nil {
		return err
	}

	ns.Name = name

	return crud.Create(bctx, p.manipulator, ns, crud.OptionPostWriteHook(p.makeNotify(bctx.Request().Operation)))
}

// ProcessRetrieveMany handles the retrieve many requests for Namespaces.
func (p *NamespacesProcessor) ProcessRetrieveMany(bctx bahamut.Context) error {
	return crud.RetrieveMany(bctx, p.manipulator, &api.NamespacesList{})
}

// ProcessRetrieve handles the retrieve requests for Namespaces.
func (p *NamespacesProcessor) ProcessRetrieve(bctx bahamut.Context) error {
	return crud.Retrieve(bctx, p.manipulator, api.NewNamespace())
}

// ProcessUpdate handles the update requests for Namespaces.
func (p *NamespacesProcessor) ProcessUpdate(bctx bahamut.Context) error {
	return crud.Update(bctx, p.manipulator, bctx.InputData().(*api.Namespace),
		crud.OptionPostWriteHook(p.makeNotify(bctx.Request().Operation)),
	)
}

// ProcessDelete handles the delete requests for Namespaces.
func (p *NamespacesProcessor) ProcessDelete(bctx bahamut.Context) error {
	return crud.Delete(bctx, p.manipulator, api.NewNamespace(),
		crud.OptionPostWriteHook(func(obj elemental.Identifiable) {

			ndr := api.NewNamespaceDeletionRecord()
			ndr.Namespace = obj.(*api.Namespace).Name
			ndr.DeleteTime = time.Now()

			if err := p.manipulator.Create(manipulate.NewContext(bctx.Context()), ndr); err != nil {
				slog.Error("Unable to create namespace deletion record",
					"namespace", ndr.Namespace,
					err,
				)
			}

			p.makeNotify(bctx.Request().Operation)(obj)
		}),
	)
}

// ProcessInfo handles the info request for Namespaces.
func (p *NamespacesProcessor) ProcessInfo(bctx bahamut.Context) error {
	return crud.Info(bctx, p.manipulator, api.NamespaceIdentity)
}

func (p *NamespacesProcessor) makeNotify(op elemental.Operation) crud.PostWriteHook {
	return func(obj elemental.Identifiable) {
		_ = notification.Publish(
			p.pubsub,
			nscache.NotificationNamespaceChanges,
			&notification.Message{
				Type: string(op),
				Data: obj.(*api.Namespace).Name,
			},
		)
	}
}

func alignNamespacName(name string, namespace string) (string, error) {

	if name == "/" {
		return "", elemental.NewError(
			"Validation Error",
			"You cannot create the / namespace",
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	if name == "" {
		return "", elemental.NewError(
			"Validation Error",
			"Empty namespace name",
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	if strings.HasSuffix(name, "/") {
		return "", elemental.NewError(
			"Validation Error",
			"Namespace must not terminate with /",
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	if strings.Contains(name, "//") {
		return "", elemental.NewError(
			"Validation Error",
			"Namespace must not contain consecutive /",
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	if namespace == "" {
		return "", elemental.NewError(
			"Validation Error",
			"Empty namespace",
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	if namespace == "/" {
		namespace = ""
	}

	// If there is no slash, it's relative
	// we just append the name to the namespace.
	if !strings.Contains(name, "/") {
		return strings.Join([]string{namespace, name}, "/"), nil
	}

	// Otherwise, we split on /
	// And get the first parts
	parts := strings.Split(name, "/")
	first := strings.Join(parts[:len(parts)-1], "/")

	// If this first part is not the same as the
	// request namespace, it's game over
	if first != namespace {
		return "", elemental.NewError(
			"Validation Error",
			fmt.Sprintf("Full namespace name must be prefixed with request namespace. got: %s", first),
			"a3s",
			http.StatusUnprocessableEntity,
		)
	}

	return name, nil
}
