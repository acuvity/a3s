package permissions

import (
	mapset "github.com/deckarep/golang-set"
)

// Match verifies the given expression matches the given claims.
func Match(expression [][]string, claims []string) bool {

	tm := mapset.NewSetFromSlice(stringListToInterfaceList(claims))

	for _, ands := range expression {
		if mapset.NewSetFromSlice(stringListToInterfaceList(ands)).IsSubset(tm) {
			return true
		}
	}

	return false
}

func stringListToInterfaceList(in []string) (out []any) {
	out = make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}

	return out
}
