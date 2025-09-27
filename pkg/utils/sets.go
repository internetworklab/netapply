package utils

// returns: (added, removed)
// added is those in lhs but not rhs, removed is those in rhs but not lhs
func DiffSets(lhs, rhs map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	added := make(map[string]interface{})
	for k, v := range lhs {
		if _, ok := rhs[k]; !ok {
			added[k] = v
		}
	}

	removed := make(map[string]interface{})
	for k, v := range rhs {
		if _, ok := lhs[k]; !ok {
			removed[k] = v
		}
	}

	return added, removed
}
