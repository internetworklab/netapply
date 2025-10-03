# Netapply

## What is This

Netapply is a declarative network configuration utility. You define the desired state of network configuration in structured text like YAML, then netapply will apply such configuration for you and ensure that the actual state eventually converge to the spec.

## How to Install

Currently only linux systems are supported:

```shell
go install github.com/internetworklab/netapply@latest
```

Or you may build it from the source:

```shell
git clone github.com/internetworklab/netapply
cd netapply
go build -o bin/netapply ./main.go
```

## How it Works

Here's the main steps the program takes:

1. Parse the YAML file from stdin/file/URL, and yields an object of struct type [`GlobalConfig`](./pkg/models/types.go#L15) if success, which is simply a dictionary that maps node name to node's [`NodeConfig`](./pkg/models/types.go#L35) .
2. Many golang receiver methods are bound to the [`NodeConfig`](./pkg/models/types.go#L35) struct type, it calls [`Up()`](./pkg/models/methods.go#L14) to realize the specified `NodeConfig` into current node. It detects the differences between the spec and the actual state in current node, and reconverges both.
3. During the reconverging process, it may creates and starts necessary containers (using docker sdk), creates and setups necessary (virtual) network interfaces (using netlink), but it mainly relys on container to separate the affects from the host environments.
4. You can clean all containers it ever created by invoke `netapply down --service-name <servicename>`, so that it stops and removes all containers it ever created.

## Example configurations

(Example configuration YAMLs are on the way ...)

## Others

About how to generate keys for OpenVPN2 serverside and clientside:

1. Generate server's DH parameters by `./generate-dh-param.sh` if it is not generated yet;
2. Generate client's cert pair by `./generate-client.sh`, modify the CN field for a different CommonName;
3. Generate server's cert pair by `./generate-server.sh`, modify the CN field for a different CommonName.

