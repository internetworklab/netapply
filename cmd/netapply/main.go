//go:generate sh -c "echo CommitHash: $(git rev-parse HEAD) > commit.txt"
//go:generate sh -c "echo BuildTime: $(date --utc --iso-8601=seconds) >> commit.txt"
//go:generate sh -c "echo RevisionOrTag: $(git describe --exact-match --tags) >> commit.txt"
//go:generate sh -c "echo GoVersion: $(go version) >> commit.txt"
//go:generate sh -c "echo Uname-srvm: $(uname -srvm) >> commit.txt"
//go:generate sh -c "echo OfficialSite: https://github.com/internetworklab/netapply >> commit.txt"
//go:generate sh -c "echo License: MIT >> commit.txt"
//go:generate sh -c "echo 'Copyright: Copyright (c) 2025 duststars' >> commit.txt"

package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	pkgcli "github.com/internetworklab/netapply/pkg/cli"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

//go:embed commit.txt
var CommitHash string

func main() {
	var cli pkgcli.CLI
	ctx := kong.Parse(&cli)
	cli.VersionMetadata = pkgutils.ParseKVPairs(":", CommitHash)
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
