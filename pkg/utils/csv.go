package utils

import "strings"

func ParseKVPairs(sep string, raw string) map[string]string {
	kvpairs := make(map[string]string)

	for _, line := range strings.Split(raw, "\n") {
		trimed := strings.TrimSpace(line)
		if trimed == "" {
			continue
		}

		sepIdx := strings.Index(trimed, sep)
		if sepIdx == -1 {
			continue
		}

		key := strings.TrimSpace(trimed[:sepIdx])
		value := strings.TrimSpace(trimed[sepIdx+len(sep):])
		kvpairs[key] = value
	}

	return kvpairs
}
