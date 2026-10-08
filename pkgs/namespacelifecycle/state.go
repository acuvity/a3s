// Package namespacelifecycle provides a dormant, private namespace-owner barrier.
// It is coordination, not authentication, a transaction, or a renewable lease.
// Namespace topology and participant adapters must retain their own single-use
// operation records and prove terminal outcomes before releasing admissions.
package namespacelifecycle

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid namespace lifecycle input")
	ErrUnavailable = errors.New("namespace lifecycle unavailable")
	ErrNotFound    = errors.New("namespace lifecycle not found")
	ErrConflict    = errors.New("namespace lifecycle conflict")
	ErrPending     = errors.New("namespace lifecycle has retained work")
	ErrUnknown     = errors.New("namespace lifecycle write outcome unknown")
)

const (
	MaxPins         = 64
	MaxDepth        = 32
	MaxParticipants = 16
	MaxStateBytes   = 64 * 1024
	maxRevision     = int64(1<<53 - 1)
)

var (
	idPattern     = regexp.MustCompile(`^[0-9a-f]{24}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyPattern    = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
	namePattern   = regexp.MustCompile(`^/[a-zA-Z0-9_/@.\-]*$`)
)

// Namespace binds an immutable native ID to its canonical absolute name.
type Namespace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Pin struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Target   Namespace      `json:"target"`
	Digest   string         `json:"digest"`
	Terminal *TerminalProof `json:"terminal,omitempty"`
}

// TerminalProof is evidence supplied by a trusted owner adapter, not a caller
// assertion. This storage kernel validates its binding/shape, not its truth.
type TerminalProof struct {
	Kind        string `json:"kind"`
	ReferenceID string `json:"referenceID"`
	Digest      string `json:"digest"`
}

type Intent struct {
	ID           string   `json:"id"`
	Digest       string   `json:"digest"`
	Participants []string `json:"participants"`
}

// DrainProof must come from the configured authenticated participant, after its
// exact local fence and terminal records have been verified. A digest is no grant.
type DrainProof struct {
	IntentID    string `json:"intentID"`
	NamespaceID string `json:"namespaceID"`
	Participant string `json:"participant"`
	Digest      string `json:"digest"`
}

// State is a detached snapshot. Reading it never restores execution authority.
type State struct {
	Version   string         `json:"version"`
	Namespace Namespace      `json:"namespace"`
	Ancestors []Namespace    `json:"ancestors"`
	Revision  int64          `json:"revision"`
	Phase     string         `json:"phase"`
	Pins      []Pin          `json:"pins"`
	Intent    *Intent        `json:"intent,omitempty"`
	Drains    []DrainProof   `json:"drains"`
	Creation  *Creation      `json:"creation,omitempty"`
	Deletion  *OwnedDeletion `json:"deletion,omitempty"`
}

func validNamespace(ref Namespace) bool {
	return idPattern.MatchString(ref.ID) && ref.ID != strings.Repeat("0", 24) &&
		len(ref.Name) <= 512 && namePattern.MatchString(ref.Name) && path.Clean(ref.Name) == ref.Name &&
		!strings.Contains(ref.Name, "//") && (ref.Name == "/" || !strings.HasSuffix(ref.Name, "/"))
}

func within(name, root string) bool {
	return name == root || root == "/" || strings.HasPrefix(name, root+"/")
}

func validIntent(i Intent) bool {
	if !keyPattern.MatchString(i.ID) || !digestPattern.MatchString(i.Digest) || len(i.Participants) == 0 || len(i.Participants) > MaxParticipants {
		return false
	}
	for j, p := range i.Participants {
		if !keyPattern.MatchString(p) || j > 0 && p <= i.Participants[j-1] {
			return false
		}
	}
	return true
}

func validPin(pin Pin, scope Namespace) bool {
	if !keyPattern.MatchString(pin.ID) || !digestPattern.MatchString(pin.Digest) || !validNamespace(pin.Target) || !within(pin.Target.Name, scope.Name) {
		return false
	}
	switch pin.Kind {
	case "namespace-create", "namespace-delete", "participant-enrollment":
	default:
		return false
	}
	return pin.Terminal == nil || validTerminal(*pin.Terminal)
}

func validTerminal(proof TerminalProof) bool {
	return (proof.Kind == "applied" || proof.Kind == "not-started") && keyPattern.MatchString(proof.ReferenceID) && digestPattern.MatchString(proof.Digest)
}

func validState(s State) bool {
	if (s.Version != "namespace-lifecycle.v1" && s.Version != "namespace-lifecycle.v2") || !validNamespace(s.Namespace) || s.Revision < 1 || s.Revision > maxRevision || len(s.Ancestors) >= MaxDepth || len(s.Pins) > MaxPins || len(s.Drains) > MaxParticipants {
		return false
	}
	previous := Namespace{}
	seen := map[string]bool{s.Namespace.ID: true}
	for i, ref := range s.Ancestors {
		if !validNamespace(ref) || seen[ref.ID] || i == 0 && ref.Name != "/" || i > 0 && path.Dir(ref.Name) != previous.Name {
			return false
		}
		seen[ref.ID], previous = true, ref
	}
	if s.Namespace.Name == "/" {
		if len(s.Ancestors) != 0 {
			return false
		}
	} else if len(s.Ancestors) == 0 || path.Dir(s.Namespace.Name) != previous.Name {
		return false
	}
	if !validCreation(s) || !validOwnedDeletion(s) {
		return false
	}
	if s.Phase == "forming" {
		return s.Version == "namespace-lifecycle.v2"
	}
	for i, pin := range s.Pins {
		if !validPin(pin, s.Namespace) || i > 0 && pin.ID <= s.Pins[i-1].ID {
			return false
		}
	}
	if s.Phase == "open" {
		return len(s.Drains) == 0 && (s.Intent == nil || s.Deletion != nil)
	}
	if s.Namespace.Name == "/" || s.Intent == nil || !validIntent(*s.Intent) {
		return false
	}
	for i, p := range s.Drains {
		if p.IntentID != s.Intent.ID || p.NamespaceID != s.Namespace.ID || !slices.Contains(s.Intent.Participants, p.Participant) || !digestPattern.MatchString(p.Digest) || i > 0 && p.Participant <= s.Drains[i-1].Participant {
			return false
		}
	}
	switch s.Phase {
	case "closing":
		return len(s.Drains) == 0 || len(s.Pins) == 0
	case "attempted", "deleted":
		return len(s.Pins) == 0 && len(s.Drains) == len(s.Intent.Participants)
	default:
		return false
	}
}

func encode(s State) (string, error) {
	if !validState(s) {
		return "", ErrInvalid
	}
	b, err := json.Marshal(s)
	if err != nil || len(b) > MaxStateBytes {
		return "", ErrInvalid
	}
	return string(b), nil
}

func decode(data string) (State, error) {
	if len(data) > MaxStateBytes {
		return State{}, ErrUnavailable
	}
	var s State
	d := json.NewDecoder(strings.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return State{}, ErrUnavailable
	}
	canonical, err := encode(s)
	if err != nil || canonical != data {
		return State{}, ErrUnavailable
	}
	return s, nil
}

// Reserve the exact worst-case encoded terminal and deletion metadata before
// admitting work. This is byte capacity, not a claim of disk availability.
func admissionFits(s State) bool {
	future := copyState(s)
	future.Phase = "attempted"
	future.Revision = maxRevision
	future.Intent = &Intent{ID: strings.Repeat("d", 128), Digest: strings.Repeat("d", 64)}
	future.Drains = nil
	for i := range MaxParticipants {
		participant := string(rune('a'+i)) + strings.Repeat("p", 127)
		future.Intent.Participants = append(future.Intent.Participants, participant)
		future.Drains = append(future.Drains, DrainProof{IntentID: future.Intent.ID, NamespaceID: s.Namespace.ID, Participant: participant, Digest: strings.Repeat("d", 64)})
	}
	for i := range future.Pins {
		future.Pins[i].Terminal = &TerminalProof{Kind: "not-started", ReferenceID: strings.Repeat("r", 128), Digest: strings.Repeat("d", 64)}
	}
	// Deliberately a sizing envelope: pins and final proofs cannot coexist in a
	// real attempted state. Do not pass this envelope through state validation.
	encoded, err := json.Marshal(future)
	reserved := 0
	if future.Creation != nil {
		owner, ownerErr := json.Marshal(future.Creation)
		if ownerErr != nil || len(owner) > maxCreationBytes {
			return false
		}
		reserved = maxCreationBytes - len(owner) + maxOwnedDeletionBytes
		if future.Deletion != nil {
			deletion, err := json.Marshal(future.Deletion)
			if err != nil || len(deletion) > maxOwnedDeletionBytes {
				return false
			}
			reserved -= len(deletion)
		}
	}
	return err == nil && len(encoded)+reserved <= MaxStateBytes
}

// Every accepted transition reserves the remaining monotonic path, including
// synthetic/legacy counter boundaries. No reset or replacement is a recovery.
func progressRevisions(s State) int64 {
	var needed int64
	for _, pin := range s.Pins {
		needed++ // exact release
		if pin.Terminal == nil {
			needed++ // durable terminal proof
		}
	}
	switch s.Phase {
	case "forming":
		// Reserve bounded source/ancestor/enrollment progress before ownership.
		needed += 5*MaxDepth + 3*MaxParticipants + 8
	case "open":
		needed += 1 + MaxParticipants + 2 // seal, proofs, attempt, confirm
		if s.Creation != nil {
			needed += 5*MaxDepth + 4 // retained source deletion ownership
		}
	case "closing":
		needed += int64(len(s.Intent.Participants)-len(s.Drains)) + 2
	case "attempted":
		needed++
	}
	if s.Deletion != nil {
		for _, phase := range s.Deletion.Acquisitions {
			switch phase {
			case "planned":
				needed += 4
			case "attempted":
				needed += 3
			case "held":
				needed += 2
			case "terminal":
				needed++
			}
		}
	}
	return needed
}

func copyState(s State) State {
	b, _ := json.Marshal(s)
	var result State
	_ = json.Unmarshal(b, &result)
	return result
}
