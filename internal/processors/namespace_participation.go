package processors

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

const namespaceParticipationMaxBytes = 32 * 1024

var (
	participationID        = regexp.MustCompile(`^[0-9a-f]{24}$`)
	participationOperation = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
)

// NamespaceParticipationStore permits an owned storage seam without weakening
// native request authentication. A cold Get never grants enrollment authority.
type NamespaceParticipationStore interface {
	Get(context.Context, string) (namespacelifecycle.State, error)
	ClaimCreationEnrollment(context.Context, namespacelifecycle.State, string, string) (namespacelifecycle.State, bool, error)
}

// NamespaceParticipationProcessor is deliberately not registered by normal main
// or configuration. Explicit composition must also retain the native auth chain.
type NamespaceParticipationProcessor struct {
	store      NamespaceParticipationStore
	authorizer *NamespaceParticipationAuthorizer
	capture    *namespacelifecycle.CaptureInspector
}

func NewNamespaceParticipationProcessor(store NamespaceParticipationStore, authorizer *NamespaceParticipationAuthorizer) (*NamespaceParticipationProcessor, error) {
	if store == nil || authorizer == nil || authorizer.authenticator == nil || authorizer.retriever == nil {
		return nil, namespacelifecycle.ErrInvalid
	}
	return &NamespaceParticipationProcessor{store: store, authorizer: authorizer}, nil
}

type namespaceParticipationCommand struct {
	Action           string `json:"action"`
	NamespaceID      string `json:"namespaceID"`
	OperationID      string `json:"operationID"`
	Participant      string `json:"participant"`
	RegistryID       string `json:"registryID"`
	DeletionIntentID string `json:"deletionIntentID,omitempty"`
}

type namespaceParticipationResult struct {
	Granted  bool                                  `json:"granted"`
	Snapshot namespacelifecycle.EnrollmentSnapshot `json:"snapshot"`
}

func participationError(status int) error {
	return elemental.NewError(http.StatusText(status), "Namespace participation is held", "a3s", status)
}

// Decode the owned flat command, rejecting duplicates, unknown/case-folded keys,
// nulls and trailing values rather than accepting generated-model defaults.
func participationCommand(r *elemental.Request) (namespaceParticipationCommand, error) {
	var out namespaceParticipationCommand
	bad := participationError(http.StatusUnprocessableEntity)
	if r == nil || r.Identity != api.NamespaceParticipationIdentity || r.Operation != elemental.OperationCreate || r.Namespace == "" ||
		r.ObjectID != "" || r.ParentID != "" || (!r.ParentIdentity.IsEmpty() && r.ParentIdentity != elemental.RootIdentity) ||
		r.Recursive || r.Propagated || r.OverrideProtection || len(r.Parameters) != 0 || len(r.Order) != 0 || r.Page != 0 || r.PageSize != 0 || r.After != "" || r.Limit != 0 ||
		r.ContentType != elemental.EncodingTypeJSON || len(r.Data) == 0 || len(r.Data) > namespaceParticipationMaxBytes {
		return out, bad
	}
	headers := r.Headers.Values("X-Namespace")
	if len(headers) != 1 || headers[0] != r.Namespace {
		return out, bad
	}
	if h := r.HTTPRequest(); h != nil && (h.Method != http.MethodPost || h.URL.Path != "/namespaceparticipations" || h.URL.RawQuery != "") {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(r.Data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return out, bad
	}
	fields := map[string]*string{"action": &out.Action, "namespaceID": &out.NamespaceID, "operationID": &out.OperationID, "participant": &out.Participant, "registryID": &out.RegistryID, "deletionIntentID": &out.DeletionIntentID}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return out, bad
		}
		name, ok := key.(string)
		field, exists := fields[name]
		if !ok || !exists {
			return out, bad
		}
		value, err := d.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			return out, bad
		}
		*field = text
		delete(fields, name)
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return out, bad
	}
	if _, err := d.Token(); err != io.EOF {
		return out, bad
	}
	if out.Action == "CaptureScope" {
		// No client namespace/operation/registry assertions, even empty ones.
		if len(fields) != 4 || fields["action"] != nil || fields["participant"] != nil || out.Participant != "hanni" {
			return out, bad
		}
		return out, nil
	}
	if len(fields) > 1 || len(fields) == 1 && fields["deletionIntentID"] == nil {
		return out, bad
	}
	if (out.Action != "Inspect" && out.Action != "ClaimEnrollment" && out.Action != "InspectDeletion") || !participationID.MatchString(out.NamespaceID) || out.NamespaceID == strings.Repeat("0", 24) ||
		out.RegistryID != out.NamespaceID || !participationOperation.MatchString(out.OperationID) || out.Participant != "hanni" {
		return out, bad
	}
	if out.Action == "InspectDeletion" {
		if !participationOperation.MatchString(out.DeletionIntentID) {
			return out, bad
		}
	} else if out.DeletionIntentID != "" {
		return out, bad
	}
	return out, nil
}

func (p *NamespaceParticipationProcessor) ProcessCreate(bctx bahamut.Context) error {
	command, err := participationCommand(bctx.Request())
	if err != nil {
		return err
	}
	if command.Action == "CaptureScope" {
		return p.processCapture(bctx, command)
	}
	check, err := p.authorizer.bind(bctx, command)
	if err != nil {
		return err
	}
	state, err := p.store.Get(bctx.Context(), command.NamespaceID)
	if err != nil {
		return participationError(http.StatusConflict)
	}
	if command.Action == "InspectDeletion" {
		snapshot, err := namespacelifecycle.SnapshotDeletion(state, command.Participant, command.RegistryID, command.DeletionIntentID)
		if err != nil || snapshot.Scope.Namespace.Name != bctx.Request().Namespace || snapshot.OperationID != command.OperationID {
			return participationError(http.StatusConflict)
		}
		if err := check(); err != nil {
			return err
		}
		bctx.SetOutputData(struct {
			Snapshot namespacelifecycle.DeletionSnapshot `json:"snapshot"`
		}{snapshot})
		return nil
	}
	snapshot, err := participationSnapshot(state, command, bctx.Request().Namespace)
	if err != nil {
		return err
	}
	// Storage/network work cannot extend a token's validity or detach the grant
	// from the original resource, IP, restrictions, command or namespace.
	if err := check(); err != nil {
		return err
	}
	granted := false
	if command.Action == "ClaimEnrollment" && snapshot.SourcePhase == "applied" && snapshot.Phase == "attempted" {
		next, won, err := p.store.ClaimCreationEnrollment(bctx.Context(), state, command.Participant, command.RegistryID)
		if err != nil {
			return participationError(http.StatusConflict)
		}
		if !won {
			next, err = p.store.Get(bctx.Context(), command.NamespaceID)
			if err != nil {
				return participationError(http.StatusConflict)
			}
		}
		current, err := participationSnapshot(next, command, bctx.Request().Namespace)
		if err != nil || current.Digest != snapshot.Digest || won && (current.Phase != "claimed" || current.SourcePhase != "applied") {
			return participationError(http.StatusConflict)
		}
		snapshot, granted = current, won
	}
	if err := check(); err != nil {
		return err
	}
	bctx.SetOutputData(namespaceParticipationResult{Granted: granted, Snapshot: snapshot})
	return nil
}

func participationSnapshot(state namespacelifecycle.State, command namespaceParticipationCommand, namespace string) (namespacelifecycle.EnrollmentSnapshot, error) {
	snapshot, err := namespacelifecycle.SnapshotEnrollment(state, command.Participant, command.RegistryID)
	if err != nil || state.Namespace.ID != command.NamespaceID || state.Namespace.Name != namespace || snapshot.OperationID != command.OperationID {
		return namespacelifecycle.EnrollmentSnapshot{}, participationError(http.StatusConflict)
	}
	return snapshot, nil
}
