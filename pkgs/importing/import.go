package importing

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
)

// Import preforms the importing of the given
// objects, in the given namespace, with the given label
// using the given manipulator.
//
// If removeMode is true, all the objects with the given
// label will be deleted.
//
// It is possible to import objects in subnamespaces by setting the
// imported object's "namespace" property with a relative namepace, using
// the unix './' notation.
//
// For example:
//
//	objects:
//		- name: a
//		- name: b namespace: ./subns
//
// If the base namespace is /ns, this would import object "a" in /ns  of the
// import and "b" in in /ns/subns.
//
// Subns imports must start with './'
//
// This function is not responsible for ordering of imports, and subnamespaces
// exist somehow (either already existing, of created earlier in the import)
// This function does not make any permission check, and will
// fail if the given manipulator does not bear sufficient permissions.
func Import(
	ctx context.Context,
	manager elemental.ModelManager,
	m manipulate.Manipulator,
	namespace string,
	label string,
	objects elemental.Identifiables,
	removeMode bool,
) error {

	if namespace == "" {
		return fmt.Errorf("namespace must not be empty")
	}

	if label == "" {
		return fmt.Errorf("label must not be empty")
	}

	if manager == nil {
		return fmt.Errorf("manager must not be nil")
	}

	lst := objects.List()
	hashed := make(map[string]Importable, len(lst))

	// If the mode is ImportModeRemove, we don't populate
	// the hashed list, which will end up deleting all
	// existing objects.
	if !removeMode {

		for i, obj := range lst {

			imp, ok := obj.(Importable)
			if !ok {
				return fmt.Errorf("object '%s[%d]' is not importable", obj.Identity().Name, i)
			}

			if ns := imp.GetNamespace(); ns != "" {
				if !strings.HasPrefix(ns, "./") {
					return fmt.Errorf("object '%s[%d] has a non relative namespace set: %s", obj.Identity(), i, ns)
				}
			}

			h, err := Hash(imp, manager)
			if err != nil {
				return fmt.Errorf("unable to hash '%s[%d]': %w", obj.Identity().Name, i, err)
			}

			imp.SetImportHash(h)
			imp.SetImportLabel(label)

			hashed[h] = imp
		}
	}

	// Now, if the objects are retrievable and deletable, we retrieve all existing object in the namespace
	// using the same import label. Otherwise we skip directly to the creation.
	if r, ok := manager.Relationships()[objects.Identity()]; ok && len(r.RetrieveMany) > 0 && len(r.Delete) > 0 {

		currentObjects := manager.Identifiables(objects.Identity())
		if err := m.RetrieveMany(
			manipulate.NewContext(
				ctx,
				manipulate.ContextOptionNamespace(namespace),
				manipulate.ContextOptionRecursive(true),
				manipulate.ContextOptionFilter(
					elemental.NewFilterComposer().
						WithKey("importLabel").Equals(label).
						Done(),
				),
			),
			currentObjects,
		); err != nil {
			return fmt.Errorf("unable to retrieve list of current %s: %w", currentObjects.Identity().Category, err)
		}

		// Then, we delete all the existing objects that have a hash
		// that is not matching any of the imported objects.
		// We also delete from the list of objects to import all the
		// ones that have a matching hash, since they did not change.
		for _, o := range currentObjects.List() {

			obj := o.(Importable)
			h := obj.GetImportHash()

			if _, ok := hashed[h]; ok {
				delete(hashed, h)
				continue
			}

			if err := m.Delete(
				manipulate.NewContext(
					ctx,
					manipulate.ContextOptionNamespace(obj.GetNamespace()),
					manipulate.ContextOptionOverride(true),
				),
				o,
			); err != nil {
				if elemental.IsErrorWithCode(err, http.StatusNotFound) {
					continue
				}
				return fmt.Errorf("unable to delete existing %s: %w", obj.Identity().Name, err)
			}
		}
	}

	// Finally, we create the remaining objects.
	for _, o := range hashed {

		ns := namespace
		if localns := o.GetNamespace(); localns != "" {
			ns = ns + "/" + strings.Replace(localns, "./", "", 1)
			o.SetNamespace("")
		}

		if err := m.Create(
			manipulate.NewContext(
				ctx,
				manipulate.ContextOptionNamespace(ns),
			),
			o,
		); err != nil {
			return fmt.Errorf("unable to create object '%s': %w", o.Identity().Name, err)
		}
	}

	return nil
}
