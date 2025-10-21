#!/bin/bash

scriptPath=$(realpath $0)
scriptDir=$(dirname $scriptPath)

cat $scriptDir/example_wgplan.yaml | \
    go run main.go generate \
        --plan-file=- \
        --keys-out-dir=$scriptDir/keys \
        --wg-confs-out-file=$scriptDir/example_wgconfs-out.yaml \
        --plaintext-keys \
        --write-to-node-directory=$scriptDir/example_nodes_out \
            >$scriptDir/example_wgplan-out.yaml
