package authorizer

import "sort"

func FlattenTags(term [][]string) (out []string) {

	set := map[string]struct{}{}

	for _, rows := range term {
		for _, r := range rows {
			set[r] = struct{}{}
		}
	}

	out = make([]string, len(set))
	var i int
	for k := range set {
		out[i] = k
		i++
	}

	sort.Strings(out)

	return out
}
