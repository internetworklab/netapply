package utils

import (
	"context"
	"log"
	"os"
	"path"
)

func GetStatefulDir(ctx context.Context) string {
	statefulDir, err := StatefulDirFromCtx(ctx)
	if err != nil || statefulDir == "" {
		log.Printf("stateful dir cannot be obtained from context, will using the default one")
		cwd, err := os.Getwd()
		if err != nil {
			panic(err)
		}

		statefulDir = path.Join(cwd, ".go-reconciler-state")
		log.Printf("using default stateful dir: %s", statefulDir)
	}
	return statefulDir
}
