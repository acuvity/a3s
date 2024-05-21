package auditor

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"

	"github.com/andreyvit/diff"
	"github.com/mitchellh/mapstructure"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

// Constants for notification topics.
const (
	NotificationAudit = "notifications.audit"
)

// MetadataKeyAudit is the bahamut.Context metadata key
// that will contain the list of recorded keyed values.
var MetadataKeyAudit = struct{}{}

// AuditMessage outlines what an audit notification will contain.
type AuditMessage struct {
	Operation elemental.Operation
	Identity  elemental.Identity
	ID        string
	Name      string
	Namespace string
	ClaimsMap map[string]string
	Diff      string
	Error     string
}

// Auditor outlines what an auditor contains.
type Auditor struct {
	manager           elemental.ModelManager
	pubsub            bahamut.PubSubClient
	trackedIdentities map[elemental.Identity]*TrackedIdentity
	ignoredAttributes []string

	bahamut.Auditer
}

// TrackedIdentity contains the indetity we want to track across the specified
// operations. If operations are empty it will track all actions.
type TrackedIdentity struct {
	Identity   elemental.Identity
	Operations []elemental.Operation
}

// NewAuditor returns a new Auditor.
func NewAuditor(manager elemental.ModelManager, pubsub bahamut.PubSubClient, options ...Option) *Auditor {

	cfg := config{}
	for _, o := range options {
		o(&cfg)
	}

	trackedIdentities := map[elemental.Identity]*TrackedIdentity{}

	for _, trackedIdentity := range cfg.trackedIdentities {
		trackedIdentities[trackedIdentity.Identity] = trackedIdentity
	}

	return &Auditor{
		manager:           manager,
		pubsub:            pubsub,
		trackedIdentities: trackedIdentities,
		ignoredAttributes: cfg.ignoredAttributes,
	}
}

// Audit pushes the audit message to nats.
func (a *Auditor) Audit(bctx bahamut.Context, err error) {

	if len(a.trackedIdentities) != 0 {
		trackedIdentity, ok := a.trackedIdentities[bctx.Request().Identity]
		if !ok {
			return
		}

		if len(trackedIdentity.Operations) != 0 && !slices.Contains(trackedIdentity.Operations, bctx.Request().Operation) {
			return
		}
	}

	msg := &AuditMessage{
		Operation: bctx.Request().Operation,
		Identity:  bctx.Request().Identity,
		Namespace: bctx.Request().Namespace,
		ClaimsMap: bctx.ClaimsMap(),
	}

	if err != nil {
		msg.Error = err.Error()
	}

	if obj := bctx.Metadata(MetadataKeyAudit); obj != nil {
		switch metadata := obj.(type) {
		case []string:
			for _, m := range metadata {
				for i := 0; i < len(m); i++ {
					if m[i] != '=' {
						continue
					}

					if i+1 >= len(m) {
						slog.Error("Missing value in metadata", "metadata", m)
						break
					}

					msg.ClaimsMap[m[:i]] = m[i+1:]
					break
				}
			}

		default:
			slog.Error("Unsupported type for metadata", "metadata", metadata)
		}
	}

	var outputData map[string]any
	if ierr := mapstructure.Decode(bctx.OutputData(), &outputData); ierr != nil {
		slog.Error("Issue decoding output data", ierr)
		return
	}

	if val, ok := outputData["ID"]; ok {
		if id, ok := val.(string); ok {
			msg.ID = id
		}
	}

	if val, ok := outputData["name"]; ok {
		if name, ok := val.(string); ok {
			msg.Name = name
		}
	}

	if err == nil && (msg.Operation == elemental.OperationUpdate || msg.Operation == elemental.OperationPatch) {
		if diff, err := a.computeDiff(bctx, outputData); err != nil {
			slog.Error("Cannot compute diff", err)
		} else {
			msg.Diff = diff
		}
	}

	if err = notification.Publish(
		a.pubsub,
		NotificationAudit,
		&notification.Message{
			Type: string(msg.Operation),
			Data: msg,
		},
	); err != nil {
		slog.Error("Issue publishing audit message", err)
	}
}

// computeDiff attempts to create the diff between the original and
// output data. It will strip unexposed, secrets, encrypted, and
// specified attributes before computing the diff.
func (a *Auditor) computeDiff(bctx bahamut.Context, outputData map[string]any) (string, error) {

	if bctx.OriginalData() == nil {
		return "", fmt.Errorf("no original data provided for identity '%s'", bctx.Request().Identity.Name)
	}

	attSpec, ok := a.manager.Identifiable(bctx.OriginalData().Identity()).(elemental.AttributeSpecifiable)
	if !ok {
		return "", fmt.Errorf("identity '%s' is not attribute specifiable", bctx.OriginalData().Identity().Name)
	}

	var origData map[string]any
	if err := mapstructure.Decode(bctx.OriginalData(), &origData); err != nil {
		return "", fmt.Errorf("issue decoding original data: %w", err)
	}

	// Strip out any specified ignored identities
	for _, key := range a.ignoredAttributes {
		delete(origData, key)
		delete(outputData, key)
	}

	for key := range origData {
		spec := attSpec.SpecificationForAttribute(strings.ToLower(key))

		if spec.Exposed && !spec.Secret && !spec.Encrypted {
			continue
		}

		delete(origData, key)
		delete(outputData, key)
	}

	if reflect.DeepEqual(origData, outputData) {
		return "", nil
	}

	// Minimize the diff to just the attributes that are truly different
	for key, origVal := range origData {
		outVal, ok := outputData[key]
		if !ok {
			continue
		}

		if !reflect.DeepEqual(origVal, outVal) {
			continue
		}

		delete(origData, key)
		delete(outputData, key)
	}

	jsonOrig, err := json.MarshalIndent(origData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("issue encoding original data: %w", err)
	}

	jsonOutput, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("issue encoding output data: %w", err)
	}

	return diff.LineDiff(string(jsonOrig), string(jsonOutput)), nil
}
