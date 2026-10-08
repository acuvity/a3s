package namespacelifecycle

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

const maxCreationBytes = 16 * 1024

// Creation is retained for the namespace lifetime. It is source-owned operation
// coordination, never a caller grant or evidence that the namespace exists.
type Creation struct {
	Origin            string               `json:"origin"`
	OperationID       string               `json:"operationID"`
	Digest            string               `json:"digest"`
	CreatedAt         string               `json:"createdAt"`
	Participants      []string             `json:"participants"`
	Phase             string               `json:"phase"`
	Acquisitions      []string             `json:"acquisitions"`
	ApplicationDigest string               `json:"applicationDigest,omitempty"`
	Enrollments       []CreationEnrollment `json:"enrollments"`
}

type CreationEnrollment struct {
	Participant string `json:"participant"`
	Phase       string `json:"phase"`
	RegistryID  string `json:"registryID,omitempty"`
	Digest      string `json:"digest,omitempty"`
}

// EnrollmentProof is metadata returned by the trusted authenticated participant
// adapter. Shape/digest validation here does not establish that authority.
type EnrollmentProof struct {
	Participant string `json:"participant"`
	NamespaceID string `json:"namespaceID"`
	OperationID string `json:"operationID"`
	RegistryID  string `json:"registryID"`
	Digest      string `json:"digest"`
}

func validCreation(s State) bool {
	if s.Version == "namespace-lifecycle.v1" {
		return s.Creation == nil
	}
	c := s.Creation
	if c == nil || !keyPattern.MatchString(c.OperationID) || !digestPattern.MatchString(c.Digest) {
		return false
	}
	clock, err := time.Parse(time.RFC3339Nano, c.CreatedAt)
	if err != nil || clock.Year() < 1 || clock.Year() > 9999 || clock.UTC().Format(time.RFC3339Nano) != c.CreatedAt || !clock.Equal(clock.Truncate(time.Millisecond)) {
		return false
	}
	encoded, err := json.Marshal(c)
	if err != nil || len(encoded) > maxCreationBytes {
		return false
	}
	if c.Origin == "bootstrap" {
		return s.Namespace.Name == "/" && len(s.Ancestors) == 0 && c.Phase == "ready" && len(c.Participants) == 0 && len(c.Acquisitions) == 0 && len(c.Enrollments) == 0 && digestPattern.MatchString(c.ApplicationDigest) && s.Phase == "open"
	}
	if c.Origin != "create" || s.Namespace.Name == "/" || !validIntent(Intent{ID: c.OperationID, Digest: c.Digest, Participants: c.Participants}) || len(c.Acquisitions) != len(s.Ancestors) || len(c.Enrollments) != len(c.Participants) {
		return false
	}
	for i, enrollment := range c.Enrollments {
		if enrollment.Participant != c.Participants[i] {
			return false
		}
		switch enrollment.Phase {
		case "planned":
			if enrollment.RegistryID != "" || enrollment.Digest != "" {
				return false
			}
		case "attempted", "claimed":
			if enrollment.RegistryID != s.Namespace.ID || enrollment.Digest != "" {
				return false
			}
		case "confirmed":
			if enrollment.RegistryID != s.Namespace.ID || !digestPattern.MatchString(enrollment.Digest) {
				return false
			}
		default:
			return false
		}
		if i > 0 && c.Enrollments[i-1].Phase != "confirmed" && enrollment.Phase != "planned" {
			return false
		}
	}
	allPlannedEnroll := true
	for _, e := range c.Enrollments {
		allPlannedEnroll = allPlannedEnroll && e.Phase == "planned"
	}
	if c.Phase != "ready" && (s.Phase != "forming" || len(s.Pins) != 0 || s.Intent != nil || len(s.Drains) != 0) {
		return false
	}
	switch c.Phase {
	case "prepared":
		return allAcquisitions(c, "planned") && allPlannedEnroll && c.ApplicationDigest == ""
	case "claimed":
		pastHeld := false
		for _, a := range c.Acquisitions {
			if a == "held" && !pastHeld {
				continue
			}
			if a == "attempted" && !pastHeld {
				pastHeld = true
				continue
			}
			if a != "planned" {
				return false
			}
			pastHeld = true
		}
		return allPlannedEnroll && c.ApplicationDigest == ""
	case "native-attempted":
		return allAcquisitions(c, "held") && allPlannedEnroll && c.ApplicationDigest == ""
	case "applied", "ready":
		digest, err := CreationMarkerDigest(s)
		if err != nil || c.ApplicationDigest != digest {
			return false
		}
		pastHeld := false
		for _, a := range c.Acquisitions {
			if a == "held" && !pastHeld {
				continue
			}
			if a == "terminal" && !pastHeld {
				pastHeld = true
				continue
			}
			if a != "released" {
				return false
			}
			pastHeld = true
		}
		if !allAcquisitions(c, "held") && !allEnrolled(c) {
			return false
		}
		if c.Phase == "ready" {
			return allAcquisitions(c, "released") && allEnrolled(c) && s.Phase != "forming"
		}
		return true
	default:
		return false
	}
}

func allAcquisitions(c *Creation, phase string) bool {
	for _, a := range c.Acquisitions {
		if a != phase {
			return false
		}
	}
	return true
}
func allEnrolled(c *Creation) bool {
	for _, e := range c.Enrollments {
		if e.Phase != "confirmed" {
			return false
		}
	}
	return true
}

// ReserveCreation reserves a fresh source incarnation/name. It is only called
// by trusted namespace-owner composition with authoritative ancestor bindings.
// It never adopts a v1 record or changes an existing reservation.
func (s *Store) ReserveCreation(ctx context.Context, ref Namespace, ancestors []Namespace, creation Creation) (State, error) {
	if creation.Origin != "" || creation.Phase != "" || len(creation.Acquisitions) != 0 || creation.ApplicationDigest != "" || len(creation.Enrollments) != 0 {
		return State{}, ErrInvalid
	}
	creation.Origin, creation.Phase = "create", "prepared"
	creation.Participants = slices.Clone(creation.Participants)
	creation.Acquisitions = make([]string, len(ancestors))
	for i := range creation.Acquisitions {
		creation.Acquisitions[i] = "planned"
	}
	creation.Enrollments = make([]CreationEnrollment, len(creation.Participants))
	for i, p := range creation.Participants {
		creation.Enrollments[i] = CreationEnrollment{Participant: p, Phase: "planned"}
	}
	state := State{Version: "namespace-lifecycle.v2", Namespace: ref, Ancestors: ancestors, Revision: 1, Phase: "forming", Pins: []Pin{}, Drains: []DrainProof{}, Creation: &creation}
	return s.initialize(ctx, state)
}

// BootstrapRoot is explicit trusted, quiescent adoption of an existing exact
// native root. The adapter must verify its immutable native source projection;
// this metadata store cannot prove quiescence or manufacture that evidence.
func (s *Store) BootstrapRoot(ctx context.Context, ref Namespace, operationID, sourceDigest string, at time.Time) (State, error) {
	if ref.Name != "/" || at.IsZero() {
		return State{}, ErrInvalid
	}
	creation := Creation{Origin: "bootstrap", OperationID: operationID, Digest: sourceDigest, CreatedAt: at.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano), Phase: "ready", Participants: []string{}, Acquisitions: []string{}, Enrollments: []CreationEnrollment{}, ApplicationDigest: sourceDigest}
	return s.initialize(ctx, State{Version: "namespace-lifecycle.v2", Namespace: ref, Ancestors: []Namespace{}, Revision: 1, Phase: "open", Pins: []Pin{}, Drains: []DrainProof{}, Creation: &creation})
}

// ClaimCreation grants only this acknowledged live invocation source-operation
// ownership. A cold read of claimed state cannot acquire or renew that right.
func (s *Store) ClaimCreation(ctx context.Context, expected State) (State, bool, error) {
	if !validState(expected) || expected.Creation == nil {
		return State{}, false, ErrInvalid
	}
	if expected.Creation.Phase != "prepared" {
		return State{}, false, nil
	}
	next := copyState(expected)
	next.Creation.Phase = "claimed"
	return s.cas(ctx, expected, next)
}
