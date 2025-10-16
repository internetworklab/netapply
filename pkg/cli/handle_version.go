package cli

import (
	"fmt"
	"sort"
)

type VersionCmd struct {
	CommitHash string
}

func (cmd *VersionCmd) Run(globalCLIConfig *CLI) error {
	pairs := make([][]string, 0)
	for key, value := range globalCLIConfig.VersionMetadata {
		pair := make([]string, 0)
		pair = append(pair, key)
		pair = append(pair, value)
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i][0] < pairs[j][0]
	})
	for _, pair := range pairs {
		fmt.Printf("%s: %s\n", pair[0], pair[1])
	}

	return nil
}

