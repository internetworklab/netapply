package utils

import (
	"sort"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func CompareStringSlices(lhs, rhs []string) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	lhsSorted := make([]string, 0)
	lhsSorted = append(lhsSorted, lhs...)
	rhsSorted := make([]string, 0)
	rhsSorted = append(rhsSorted, rhs...)
	sort.Strings(lhsSorted)
	sort.Strings(rhsSorted)

	for i := range lhsSorted {
		if lhsSorted[i] != rhsSorted[i] {
			return false
		}
	}
	return true
}

func CompareStringPointers(lhs, rhs *string) bool {
	if lhs == nil {
		return rhs == nil
	}

	if rhs == nil {
		return false
	}

	return *lhs == *rhs
}

func CompareInt64Pointers(lhs, rhs *int64) bool {
	if lhs == nil {
		return rhs == nil
	}

	if rhs == nil {
		return false
	}

	return *lhs == *rhs
}

func CompareIntPointers(lhs, rhs *int) bool {
	if lhs == nil {
		return rhs == nil
	}

	if rhs == nil {
		return false
	}

	return *lhs == *rhs
}

func CompareBoolPointers(lhs, rhs *bool) bool {
	if lhs == nil {
		return rhs == nil
	}
	if rhs == nil {
		return false
	}
	return *lhs == *rhs
}

func IsAllZeroKey(key wgtypes.Key) bool {
	for i := range wgtypes.KeyLen {
		if key[i] != 0 {
			return false
		}
	}
	return true
}
