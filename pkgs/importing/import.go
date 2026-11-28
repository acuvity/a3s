package importing

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"

	"go.acuvity.ai/a3s/pkgs/sharder"
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
// If updateMode is true, existing objects are updated in place (preserving
// their identifier) rather than deleted and recreated. In both modes the
// import describes the full desired state for the label: existing objects
// carrying the label that are not present in the imported set are deleted.
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
//
// sm is a system-level manipulator used only for read operations (checking
// for pre-existing objects). All write operations use m.
//
// To import several kinds of objects that reference each other under one
// label, use ImportLists: it orders the deletions after every creation and
// update.
func Import(
	ctx context.Context,
	manager elemental.ModelManager,
	m manipulate.Manipulator,
	sm manipulate.Manipulator,
	namespace string,
	label string,
	objects elemental.Identifiables,
	removeMode bool,
	updateMode bool,
	hasher sharder.Hasher,
) error {

	return ImportLists(
		ctx,
		namespace,
		label,
		[]List{{
			Objects:           objects,
			Manager:           manager,
			Manipulator:       m,
			SystemManipulator: sm,
			UpdateMode:        updateMode,
		}},
		removeMode,
		hasher,
	)
}

// A List is one kind of objects to import with ImportLists, and what serves
// them.
type List struct {
	// Objects are the objects to import.
	Objects elemental.Identifiables

	// Manager is the model manager of the objects.
	Manager elemental.ModelManager

	// Manipulator writes the objects, with the permissions of the caller.
	Manipulator manipulate.Manipulator

	// SystemManipulator is a system-level manipulator, only used to read the
	// objects already carrying the label.
	SystemManipulator manipulate.Manipulator

	// UpdateMode updates the existing objects in place, keeping their
	// identifier, instead of deleting and creating them again. See Import.
	UpdateMode bool
}

// ImportLists imports the given lists in the given namespace under one label,
// as Import does for each of them, but orders the work across the lists, which
// must come in dependency order: it creates and updates the objects in the order
// of the lists, then deletes the objects that are no longer imported in the
// reverse order. So an object is only deleted once the objects it imported that
// referenced it no longer do. If removeMode is true, all the objects with the
// given label are deleted, in the reverse order of the lists.
//
// In replace mode, an object that changed is still deleted then created again
// in place, as its new version would collide with the old one.
func ImportLists(
	ctx context.Context,
	namespace string,
	label string,
	lists []List,
	removeMode bool,
	hasher sharder.Hasher,
) error {

	if namespace == "" {
		return fmt.Errorf("namespace must not be empty")
	}

	if label == "" {
		return fmt.Errorf("label must not be empty")
	}

	for _, l := range lists {

		if l.Manager == nil {
			return fmt.Errorf("manager must not be nil")
		}

		if l.SystemManipulator == nil {
			return fmt.Errorf("system manipulator must not be nil")
		}
	}

	gone := make([][]Importable, len(lists))
	for i, l := range lists {
		var err error
		if gone[i], err = importList(ctx, namespace, label, l, removeMode, hasher); err != nil {
			return err
		}
	}

	for i := len(lists) - 1; i >= 0; i-- {
		for _, obj := range gone[i] {
			if err := lists[i].Manipulator.Delete(
				manipulate.NewContext(
					ctx,
					manipulate.ContextOptionNamespace(obj.GetNamespace()),
					manipulate.ContextOptionOverride(true),
				),
				obj,
			); err != nil {
				if elemental.IsErrorWithCode(err, http.StatusNotFound) {
					continue
				}
				return fmt.Errorf("unable to delete existing %s: %w", obj.Identity().Name, err)
			}
		}
	}

	return nil
}

// importList creates and updates the objects of the given list, and returns the
// objects carrying the label that it no longer imports, which the caller must
// delete.
func importList(
	ctx context.Context,
	namespace string,
	label string,
	l List,
	removeMode bool,
	hasher sharder.Hasher,
) ([]Importable, error) {

	manager := l.Manager
	m := l.Manipulator
	objects := l.Objects

	lst := objects.List()
	hashed := make(map[string]Importable, len(lst))

	// The zhashes of the imported objects tell, in replace mode, the existing
	// objects that changed, which have to be deleted before their new version
	// is created, from the ones that are gone. Without a hasher, every existing
	// object that does not match is taken as changed.
	zhashes := make(map[int]struct{}, len(lst))

	// If the mode is ImportModeRemove, we don't populate
	// the hashed list, which will end up deleting all
	// existing objects.
	if !removeMode {

		for i, obj := range lst {

			imp, ok := obj.(Importable)
			if !ok {
				return nil, fmt.Errorf("object '%s[%d]' is not importable", obj.Identity().Name, i)
			}

			localns := imp.GetNamespace()
			if localns == "" {
				imp.SetNamespace(namespace)
			} else {
				if !strings.HasPrefix(localns, "./") {
					return nil, fmt.Errorf("object '%s[%d] has a non relative namespace set: %s", obj.Identity(), i, localns)
				}
				if namespace == "/" {
					imp.SetNamespace("/" + strings.Replace(localns, "./", "", 1))
				} else {
					imp.SetNamespace(namespace + "/" + strings.Replace(localns, "./", "", 1))
				}
			}

			h, err := Hash(imp, manager)
			if err != nil {
				return nil, fmt.Errorf("unable to hash '%s[%d]': %w", obj.Identity().Name, i, err)
			}

			if s, ok := imp.(sharder.Shardable); ok && hasher != nil && !l.UpdateMode {
				if err := hasher.Hash(s); err != nil {
					return nil, fmt.Errorf("unable to compute zhash for '%s[%d]': %w", obj.Identity().Name, i, err)
				}
				zhashes[s.GetZHash()] = struct{}{}
			}

			imp.SetNamespace(localns)
			imp.SetImportHash(h)
			imp.SetImportLabel(label)

			hashed[h] = imp
		}
	}

	// Now, if the objects are retrievable and deletable, we retrieve all existing object in the namespace
	// using the same import label. Otherwise we skip directly to the creation.
	r, ok := manager.Relationships()[objects.Identity()]
	if !ok || len(r.RetrieveMany) == 0 || len(r.Delete) == 0 {
		return nil, nil
	}

	currentObjects := manager.Identifiables(objects.Identity())
	if err := l.SystemManipulator.RetrieveMany(
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
		return nil, fmt.Errorf("unable to retrieve list of current %s: %w", currentObjects.Identity().Category, err)
	}

	if removeMode {
		gone := make([]Importable, 0, len(currentObjects.List()))
		for _, o := range currentObjects.List() {
			gone = append(gone, o.(Importable))
		}
		return gone, nil
	}

	if l.UpdateMode {
		gone, err := updateImport(ctx, currentObjects, objects, manager, m, namespace, label, hasher)
		if err != nil {
			return nil, fmt.Errorf("unable to update objects: %w", err)
		}
		return gone, nil
	}

	// The existing objects that have a hash matching one of the imported
	// objects did not change: they are taken out of the objects to create.
	// The ones that changed are deleted now, so that their new version can be
	// created, and the ones that are gone are left to the caller.
	var gone []Importable
	for _, o := range currentObjects.List() {

		obj := o.(Importable)
		h := obj.GetImportHash()

		if _, ok := hashed[h]; ok {
			delete(hashed, h)
			continue
		}

		if len(zhashes) > 0 {
			if s, ok := o.(sharder.Shardable); ok {
				if err := hasher.Hash(s); err != nil {
					return nil, fmt.Errorf("unable to compute zhash for existing %s: %w", obj.Identity().Name, err)
				}
				if _, changed := zhashes[s.GetZHash()]; !changed {
					gone = append(gone, obj)
					continue
				}
			}
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
			return nil, fmt.Errorf("unable to delete existing %s: %w", obj.Identity().Name, err)
		}
	}

	// Finally, we create the remaining objects.
	for _, obj := range lst {

		o := obj.(Importable)

		if _, ok := hashed[o.GetImportHash()]; !ok {
			continue
		}

		ns := namespace
		ns = resolveNamespace(ns, o)
		if err := m.Create(
			manipulate.NewContext(
				ctx,
				manipulate.ContextOptionNamespace(ns),
			),
			o,
		); err != nil {
			return nil, fmt.Errorf("unable to create object '%s': %w", o.Identity().Name, err)
		}
	}

	return gone, nil
}

// updateImport updates the existing objects if the import hash of the incoming object is different from the existing one.
// It preserves the identifier of the existing object and backports unexposed fields from the existing object to the incoming one.
// If not found, it creates the incoming object. If the incoming object resolves to a different namespace than the existing one,
// it deletes the existing object and creates the incoming one in the new namespace. It returns the existing objects that
// are no longer imported, which the caller must delete.
func updateImport(ctx context.Context, currentObjects elemental.Identifiables, objects elemental.Identifiables, manager elemental.ModelManager, m manipulate.Manipulator, namespace string, label string, hasher sharder.Hasher) ([]Importable, error) {

	existingByZhash := make(map[int]Importable)
	for _, o := range currentObjects.List() {
		s, ok := o.(sharder.Shardable)
		if !ok {
			return nil, fmt.Errorf("object '%s' is not shardable", o.Identity().Name)
		}
		if err := calculateZhash(s, hasher); err != nil {
			return nil, fmt.Errorf("unable to compute zhash for existing %s: %w", o.Identity().Name, err)
		}
		existingByZhash[s.GetZHash()] = o.(Importable)
	}

	for _, o := range objects.List() {

		incomingObj := o.(Importable)

		incomingObj.SetImportLabel(label)
		ns := resolveNamespace(namespace, incomingObj)
		incomingObj.SetNamespace(ns)

		if err := calculateZhash(incomingObj, hasher); err != nil {
			return nil, fmt.Errorf("unable to compute zhash for %s: %w", incomingObj.Identity().Name, err)
		}

		s, ok := incomingObj.(sharder.Shardable)
		if !ok {
			return nil, fmt.Errorf("object '%s' is not shardable", incomingObj.Identity().Name)
		}
		objZhash := s.GetZHash()

		newObjHash, err := Hash(incomingObj, manager)
		if err != nil {
			return nil, fmt.Errorf("unable to hash %s: %w", incomingObj.Identity().Name, err)
		}
		incomingObj.SetImportHash(newObjHash)

		existing, ok := existingByZhash[objZhash]
		if !ok {
			slog.Debug("import by zhash: creating", "identity", incomingObj.Identity().Name, "zhash", objZhash, "namespace", ns, "hash", newObjHash)
			incomingObj.SetNamespace("")
			if err := m.Create(
				manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(ns)),
				incomingObj,
			); err != nil {
				return nil, fmt.Errorf("unable to create %s during import: %w", incomingObj.Identity().Name, err)
			}
			continue
		}
		delete(existingByZhash, objZhash)

		// If the imported object resolves to a different namespace
		// than where the existing object currently lives, we cannot
		// update it in place.
		if existing.GetNamespace() != ns {
			if err := m.Delete(
				manipulate.NewContext(
					ctx,
					manipulate.ContextOptionNamespace(existing.GetNamespace()),
					manipulate.ContextOptionOverride(true),
				),
				existing,
			); err != nil && !elemental.IsErrorWithCode(err, http.StatusNotFound) {
				return nil, fmt.Errorf("unable to delete existing %s: %w", existing.Identity().Name, err)
			}
			incomingObj.SetNamespace("")
			if err := m.Create(
				manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(ns)),
				incomingObj,
			); err != nil {
				return nil, fmt.Errorf("unable to create %s during import: %w", incomingObj.Identity().Name, err)
			}
			continue
		}

		incomingObj.SetIdentifier(existing.Identifier())
		incomingObj.SetImportHash(existing.GetImportHash())

		existingHash := existing.GetImportHash()
		slog.Debug("import by zhash: existing object found, comparing hashes", "identity", existing.Identity().Name, "zhash", objZhash, "existingHash", existingHash, "newHash", newObjHash)
		if existingHash == "dirty" {
			rehash, err := Hash(existing, manager)
			if err != nil {
				return nil, fmt.Errorf("unable to rehash dirty %s: %w", existing.Identity().Name, err)
			}
			existingHash = rehash
		}

		if existingHash == newObjHash {
			slog.Debug("import by zhash: unchanged, skipping", "identity", existing.Identity().Name, "zhash", objZhash, "hash", newObjHash)
			continue
		}

		if src, ok := existing.(elemental.AttributeSpecifiable); ok {
			if dst, ok := incomingObj.(elemental.AttributeSpecifiable); ok {
				elemental.BackportUnexposedFields(src, dst)
				backportReadOnlyFields(src, dst)
			}
		}

		if err := m.Update(
			manipulate.NewContext(ctx, manipulate.ContextOptionNamespace(existing.GetNamespace())),
			incomingObj,
		); err != nil {
			return nil, fmt.Errorf("unable to update %s during import: %w", incomingObj.Identity().Name, err)
		}
	}

	gone := make([]Importable, 0, len(existingByZhash))
	for _, existing := range existingByZhash {
		gone = append(gone, existing)
	}

	return gone, nil
}

func calculateZhash(obj elemental.Identifiable, h sharder.Hasher) error {
	s, ok := obj.(sharder.Shardable)
	if !ok {
		return nil
	}
	return h.Hash(s)
}

func resolveNamespace(ns string, object Importable) string {
	if localns := object.GetNamespace(); localns != "" {
		if ns == "/" {
			ns = "/" + strings.Replace(localns, "./", "", 1)
		} else {
			ns = ns + "/" + strings.Replace(localns, "./", "", 1)
		}
		object.SetNamespace("")
	}
	return ns
}

func backportReadOnlyFields(src, dst elemental.AttributeSpecifiable) {

	for field, spec := range src.AttributeSpecifications() {

		if !spec.ReadOnly || !spec.Exposed || spec.Transient {
			continue
		}
		vdst := reflect.ValueOf(dst)
		if !vdst.IsValid() || vdst.IsNil() {
			continue
		}
		if f := reflect.Indirect(vdst).FieldByName(field); f.IsValid() && f.CanSet() {
			f.Set(reflect.Indirect(reflect.ValueOf(src)).FieldByName(field))
		}
	}
}
