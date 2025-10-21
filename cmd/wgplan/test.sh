#!/bin/bash

scriptPath=$(realpath $0)
scriptDir=$(dirname $scriptPath)

cat $scriptDir/example_wgplan.yaml | \
    go run main.go generate \
        --plan-file=- \
        --keys-out-dir=$scriptDir/keys \
        --wg-confs-out-file=$scriptDir/example_wgconfs-out.yaml \
        --plaintext-keys \
            >$scriptDir/example_wgplan-out.yaml
