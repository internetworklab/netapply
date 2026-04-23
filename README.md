# Netapply

A **resource-centric**, declarative, netns-aware infrastructure-as-code tool for Linux networking. Define network resources in YAML and reconcile them against the kernel via netlink through a local HTTP API.

## What is This

Netapply is a network configuration daemon that treats network interfaces and protocol configurations as reconcilable resources. You declare the desired state of your network in structured YAML or JSON, send it to the local agent over HTTP, and netapply ensures the actual system state converges to the spec.

Supported resource types:

- **Dummy** — Dummy interfaces with IP addresses
- **Veth** — Virtual Ethernet pairs across network namespaces
- **Bridge** — Linux bridges with slave interfaces
- **VXLAN** — VXLAN tunnels
- **WireGuard** — WireGuard VPN tunnels
- **VRF** — Virtual Routing and Forwarding instances
- **BIRD BGP** — BIRD BGP protocol configuration snippets

## Architecture

Netapply runs as an HTTP server over a Unix domain socket. It operates in two modes:

### `serve-local` — Node Agent

Runs on each node and reconciles resources directly via netlink.

Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/resources/apply?delete=true\|false` | Apply a `NodeConfig` payload |
| `POST` | `/resources/status` | Return status of resources in the payload |
| `GET`  | `/basicinfo/version` | Build/version metadata |
| `GET`  | `/basicinfo/basicinfo` | Node basic information |

### `serve-collection` — Collection Manager

Manages resource collections backed by MongoDB. Useful for centralized WireGuard or BGP peer management.

Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/collections/wg/` | Write WireGuard configs |
| `GET`  | `/collections/wg/` | Read WireGuard configs |
| `POST` | `/collections/bgp/` | Write BIRD BGP configs |
| `GET`  | `/collections/bgp/` | Read BIRD BGP configs |
| `GET`  | `/basicinfo/version` | Build/version metadata |
| `GET`  | `/basicinfo/basicinfo` | Node basic information |

Query parameters for collection reads:

- `includedeleted=true` — Include soft-deleted documents
- Node name is extracted from the URL path: `/collections/<name>/nodes/<node_name>/...`

## Installation

Currently only Linux systems are supported.

Build from source:

```shell
git clone https://github.com/internetworklab/netapply
cd netapply
go build -o bin/netapply ./cmd/netapply/main.go
```

## Usage

### Start the local node agent

```shell
./bin/netapply serve-local \
  --bind-unix-socket /var/run/netapply.sock \
  --node mynode \
  --v6-available
```

### Start the collection manager

```shell
./bin/netapply serve-collection \
  --bind-unix-socket /var/run/netapply-collection.sock \
  --mongodb-uri "mongodb://localhost:27017" \
  --node mynode
```

### Show version

```shell
./bin/netapply version
```

### Apply a resource manifest

```shell
curl -X POST \
  --unix-socket /var/run/netapply.sock \
  -H "Content-Type: application/yaml" \
  --data-binary @examples/dummy.yaml \
  "http://localhost/resources/apply"
```

With soft-deletion enabled (remove unmanaged resources):

```shell
curl -X POST \
  --unix-socket /var/run/netapply.sock \
  -H "Content-Type: application/yaml" \
  --data-binary @examples/dummy.yaml \
  "http://localhost/resources/apply?delete=true"
```

## Configuration Format

The top-level payload for `/resources/apply` is a `NodeConfig`. It contains a single `resources` block:

```yaml
resources:
  dummy:
    containers: []
    dummies:
      - name: dummy0
        addresses:
          - cidr: "10.0.0.1/24"
  wireguard:
    containers: []
    wireguard_configs:
      - name: wg0
        privatekey: "..."
        listen_port: 51820
        peers:
          - publickey: "..."
            endpoint: "peer.example.com:51820"
            allowedips:
              - "0.0.0.0/0"
        addresses:
          - cidr: "192.168.1.1/24"
```

### Common fields

Most interface resources share these fields:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Interface name |
| `container` | object | Target netns (see below) |
| `addresses` | list | IP addresses (`cidr`, `local`, `peer`) |
| `vrf` | string | Attach interface to a VRF |
| `mtu` | int | MTU |
| `deleted` | bool | Soft-delete flag |

### Container / Netns Selection

The `container` object selects the target network namespace:

```yaml
container:
  docker: frr          # Docker container name
  podman: frr          # Podman container name
  netns_path: /run/netns/ns1   # Direct netns path
  host_netns: true     # Host namespace (dangerous)
```

Resource lists also accept a `containers` array that declares all namespaces used by that resource type. Individual resources can override with their own `container` field.

### Resource Reference

#### Dummy

```yaml
resources:
  dummy:
    containers: []
    dummies:
      - name: dummy0
        container:
          docker: router1
        addresses:
          - cidr: "10.1.0.1/24"
        vrf: vrf101
```

#### Veth

```yaml
resources:
  veth:
    containers: []
    veth_pairs:
      - name: veth0
        container:
          docker: router1
        addresses:
          - cidr: "10.1.1.1/30"
        peer:
          name: veth0-a
          container:
            docker: router2
          addresses:
            - cidr: "10.1.1.2/30"
```

A `stub: true` peer represents the remote end of a veth pair that lives in another netns and is managed by a separate spec.

#### Bridge

```yaml
resources:
  bridge:
    containers: []
    bridges:
      - name: br0
        container:
          docker: router1
        slave_interfaces:
          - veth0-a
          - vxlan101
        addresses:
          - cidr: "10.1.2.1/24"
```

#### VXLAN

```yaml
resources:
  vxlan:
    containers: []
    vxlan_configs:
      - name: vxlan101
        container:
          docker: router1
        vxlan_id: 101
        local_ip: "10.1.0.1"
        dst_port: 4789
        nolearning: true
        dev: eth0
```

#### WireGuard

```yaml
resources:
  wireguard:
    containers: []
    wireguard_configs:
      - name: wg0
        container:
          docker: router1
        privatekey: "..."
        listen_port: 51820
        peers:
          - publickey: "..."
            presharedkey: "..."
            endpoint: "peer.example.com:51820"
            allowedips:
              - "0.0.0.0/0"
              - "::/0"
        addresses:
          - cidr: "192.168.100.1/24"
        vrf: vrf101
        additionals:
          asn: "4242420001"
```

#### VRF

```yaml
resources:
  vrf_list:
    containers: []
    vrfs:
      - name: vrf101
        container:
          docker: router1
        table_id: 101
        addresses:
          - cidr: "10.1.0.1/24"
```

#### BIRD BGP

```yaml
resources:
  bird_bgp:
    target_config_directory: /etc/bird/peers
    bird_socket_path: /var/run/bird/bird.ctl
    ebgp_protocols:
      - name: peer1
        template: dnpeers_dualstack
        interface: eth0
        local_address: "fe80::1%eth0"
        peer_address: "fe80::2%eth0"
        local_asn: "4242420001"
        peer_asn: "4242420002"
```

## How it Works

1. **Parse** the YAML/JSON payload into a `NodeConfig`.
2. **Detect changes** for each resource type by comparing the spec against the current netlink state.
3. **Generate a changeset** containing resources to add, update, or remove.
4. **Apply** the changeset in dependency order:
   - VRF → Dummy → Veth → WireGuard → VXLAN → Bridge
5. **Re-detect** changes and repeat until converged or a loop limit is reached.

## Examples

See the [`examples/`](./examples) directory for working manifests:

- [`dummy.yaml`](./examples/dummy.yaml) — Simple dummy interface
- [`veth-bridge.yaml`](./examples/veth-bridge.yaml) — Veth pair + bridge topology
- [`vxlan.yaml`](./examples/vxlan.yaml) — VXLAN tunnel
- [`wireguard.yaml`](./examples/wireguard.yaml) — WireGuard tunnel in a netns
- [`bird-bgp.yaml`](./examples/bird-bgp.yaml) — BIRD BGP peer configurations
- [`wireguard-dn42.yaml`](./examples/wireguard-dn42.yaml) — Multi-peer WireGuard with metadata

## TLS and Authentication

Both `serve-local` and `serve-collection` support client-side TLS and HTTP Basic Auth flags:

- `--tls-trusted-ca-cert`
- `--tls-client-cert`
- `--tls-client-key`
- `--http-basic-auth-username`
- `--http-basic-auth-password`

These are used when fetching remote configuration sources (e.g., HTTPS URLs).

## License

MIT
