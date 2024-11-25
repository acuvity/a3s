package permissions

import (
	"slices"
	"strings"
)

// Permissions represents a parsed permission string.
type Permissions map[string]bool

// A PermissionMap represents a map of resource to Permissions
type PermissionMap map[string]Permissions

// Parse parses the given list of permission strings in the form
// resource:action1,...,actionN:id1,...,idN and returns the
// PermissionMap.
func Parse(authStrings []string, targetID string) PermissionMap {

	perms := PermissionMap{}

	slices.SortFunc(authStrings, func(a string, b string) int {

		aok := strings.HasPrefix(a, "-")
		bok := strings.HasPrefix(b, "-")

		if aok && !bok {
			return 1
		}

		if !aok && bok {
			return -1
		}

		return strings.Compare(a, b)
	})

	for _, item := range authStrings {

		segments := strings.SplitN(item, ":", 3)

		var resource, actions, ids string
		switch len(segments) {
		case 0, 1:
			continue
		case 2:
			resource = segments[0]
			actions = segments[1]
		case 3:
			resource = segments[0]
			actions = segments[1]
			ids = segments[2]
		}

		if len(ids) > 0 {

			// We did not receive any targetID, so this rule does not apply.
			if targetID == "" {
				continue
			}

			accept := false
			for _, tid := range strings.Split(ids, ",") {
				if tid == targetID {
					accept = true
					break
				}
			}

			if !accept {
				continue
			}
		}

		allowed := true
		if strings.HasPrefix(resource, "-") {
			resource = resource[1:]
			allowed = false
		}

		if _, ok := perms[resource]; !ok {
			perms[resource] = map[string]bool{}
		}

		for _, action := range strings.Split(actions, ",") {
			perms[resource][action] = allowed
		}
	}

	return perms
}

// Copy returns a copy of the receiver.
func (m PermissionMap) Copy() PermissionMap {

	var out = make(PermissionMap, len(m))

	for i, m := range m {
		out[i] = make(Permissions, len(m))
		for k, v := range m {
			out[i][k] = v
		}
	}
	return out
}

// Contains returns true if the receiver inclusively contains the given
// PermissionsMap.
func (m PermissionMap) Contains(other PermissionMap) bool {

	if len(m) == 0 {
		return false
	}

	star := m["*"]

	for identity, decorators := range other {

		if _, ok := m[identity]; !ok && len(star) == 0 {
			return false
		}

		for decorator := range decorators {
			if !m[identity][decorator] && !star[decorator] {
				ok1 := m[identity]["*"]
				ok2 := star["*"]
				if !ok1 && !ok2 {
					return false
				}
			}
		}
	}

	return true
}

// Intersect returns the intersection between the receiver and the given PermissionMap.
func (m PermissionMap) Intersect(other PermissionMap) PermissionMap {

	// If one or the other are empty, the intersection is nil.
	if len(m) == 0 || len(other) == 0 {
		return PermissionMap{}
	}

	// first we copy the base, since we are going to
	// modify it.
	candidate := PermissionMap{}
	for k, v := range m {
		candidate[k] = Permissions{}
		for kk, vv := range v {
			candidate[k][kk] = vv
		}
	}

	// If the candidate has a * in it,
	// we copy all the other's key in the base map
	// that are not already there
	if _, ok := candidate["*"]; ok {
		delete(candidate, "*")
		for k, v := range other {
			if _, ok := candidate[k]; !ok {
				candidate[k] = Permissions{}
				for kk, vv := range v {
					candidate[k][kk] = vv
				}
			}
		}
	}

	// If the other as a star, we keep track of
	// the general permissions
	rstartperms, rstartok := other["*"]

	// now we loop on all the permission of the out candidate
	for resource, perms := range candidate {

		// Otherwise we check check if the other
		// has the identity declared.
		rperms, ok := other[resource]

		// If it does not, and we have no * declared
		// we remove the identity from the candidate
		// and continue
		if !ok && !rstartok {
			delete(candidate, resource)
			continue
		}

		// We may have nil perms here in case
		// of no identity, but global permissions
		// so we eventually initialize the map.
		if rperms == nil {
			rperms = Permissions{}
		}

		// If we have some global perms we backport them
		// to the current set of perms.
		if rstartok {
			for k, v := range rstartperms {
				rperms[k] = v
			}
		}

		// We now check if the candidate permissions of the
		// current identity is *. If it is,
		// then we simply apply the other permissions.
		// and we continue
		if allowed, ok := perms["*"]; ok && allowed {
			candidate[resource] = rperms
			continue
		}

		// Otherwise we loop of the candidate perms.
		for perm := range perms {

			// If the restricted permissions are not here and there is
			// no * declared, we remove the permission from the candidate.
			allowed, ok := rperms[perm]
			allowedAny, okAny := rperms["*"]
			if (!ok || !allowed) && (!okAny || !allowedAny) {
				delete(perms, perm)
			}
		}
	}

	return candidate
}

// Allows returns true if the given operation on the given identity is allowed.
func (m PermissionMap) Allows(operation string, resource string) bool {

	allows := func(perms Permissions, op string) (bool, bool) {

		gallowed, gok := perms["*"]
		sallowed, sok := perms[op]

		if gok && sok {
			return gallowed && sallowed, true
		}

		if sok {
			return sallowed, true
		}

		if gok {
			return gallowed, true
		}

		return false, false
	}

	gallowed, gok := allows(m["*"], operation)
	sallowed, sok := allows(m[resource], operation)

	if gok && sok {
		return sallowed && gallowed
	}

	if gok {
		return gallowed
	}

	if sok {
		return sallowed
	}

	return false
}
