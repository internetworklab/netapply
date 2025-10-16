I'll explore the project to give you a comprehensive overview. Let me start by examining the structure and key files.

[13 tools called]

Based on my exploration of the codebase, here's a comprehensive bird's eye view of the **Netapply** project:

## What It Does

**Netapply** is a **declarative network infrastructure-as-code tool** for Linux. It allows you to:

1. **Define complex network topologies in YAML** - Specify routers, switches, tunnels, and routing protocols
2. **Automatically provision network resources** - Creates containers, virtual interfaces, tunnels (WireGuard, OpenVPN, VXLAN)
3. **Configure routing protocols** - Sets up BGP, OSPF routing using FRR (Free Range Routing)
4. **Maintain desired state** - Reconciles actual network state with declared configuration
5. **Test network scenarios** - Build lab environments for experimenting with routing protocols and network architectures

Think of it as **"Kubernetes for network labs"** - you declare what you want, and it makes it happen.

## How It Works

### Core Workflow

```
YAML Config → Parse → Detect Changes → Apply Changes → Verify
```

1. **Parse Configuration** (`main.go`)
   - Reads YAML from file/stdin/HTTPS URL
   - Deserializes into `GlobalConfig` → `NodeConfig` structures
   - Supports HTTP Basic Auth and TLS for remote configs

2. **Reconciliation Loop** (`pkg/models/methods.go`, `pkg/reconcile/`)
   - **Detects differences** between desired spec and actual state
   - **Generates changesets** (resources to add/update/remove)
   - **Applies changes** in correct order (respecting dependencies)
   - **Iterates** until convergence (max 10 loops)

3. **Three-Phase Setup** (`NodeConfig.Up()`)
   - **Phase 1: Containers** - Creates FRR containers using Docker
   - **Phase 2: Dataplane** - Sets up interfaces, tunnels, bridges
   - **Phase 3: Controlplane** - Configures routing protocols via FRR vtysh

4. **Resource Management**
   - Uses Linux **netlink** for interface manipulation
   - Uses **Docker SDK** for container lifecycle
   - Uses **network namespaces** for isolation
   - Uses **FRR vtysh** for routing protocol configuration

## Code Structure & Design Principles

### Directory Organization

```
netapply/
├── main.go                    # CLI entry point (Kong-based)
├── pkg/
│   ├── models/                # Core data models
│   │   ├── types.go          # GlobalConfig, NodeConfig, DataplaneConfig
│   │   └── methods.go        # Up(), Reconcile(), Apply() logic
│   ├── reconcile/            # Reconciliation engine
│   │   ├── types.go          # Interfaces: ResourceProvisioner, InterfaceChangeSet
│   │   └── methods.go        # DetectChanges, Apply, Merge logic
│   ├── interface/            # Network interface implementations
│   │   ├── bridge/           # Linux bridge
│   │   ├── dummy/            # Dummy interfaces
│   │   ├── veth/             # Virtual ethernet pairs
│   │   ├── vrf/              # VRF (Virtual Routing and Forwarding)
│   │   ├── vxlan/            # VXLAN tunnels
│   │   ├── wireguard/        # WireGuard VPN
│   │   └── route/            # Static routes
│   ├── protocol/             # Routing protocols
│   │   ├── bgp/              # BGP configuration
│   │   └── ospfv2/           # OSPF configuration
│   ├── frr/                  # FRR integration
│   │   ├── container/        # FRR container management
│   │   ├── vtysh/            # vtysh command execution
│   │   └── daemons/          # FRR daemon configuration
│   ├── openvpn2/             # OpenVPN support
│   ├── docker/               # Docker SDK wrapper
│   └── utils/                # Utilities (context, paths, networking)
└── examples/                 # Example YAML configurations
```

### Key Design Principles

#### 1. **Declarative Configuration**
- Users specify **desired state**, not imperative steps
- Example: "I want a WireGuard tunnel between lax1 and lax2" not "create wg interface, set keys, configure peers..."

#### 2. **Reconciliation Pattern** (Kubernetes-style)
```go
type ResourceProvisioner interface {
    Create(ctx)                        // Create if doesn't exist
    DetectChanges(ctx) ChangeSet       // Compare spec vs actual
    CheckExist(ctx) bool               // Check if resource exists
}
```

Each resource type implements this interface:
- **WireGuard**, **VXLAN**, **Veth**, **Bridge**, **OpenVPN**, etc.

#### 3. **Interface Segregation**
- `ResourceProvisioner` - For creating new resources
- `InterfaceChangeSet` - For updating existing resources  
- `ResourceCanceller` - For deleting resources
- `ResourceProvisionersList` - For managing collections

#### 4. **Dependency Ordering**
Resources created in priority order (`reconcile/methods.go:93-118`):
```
0. Tuntap (OpenVPN)
1. VRF
2. Dummy
3. Veth
4. WireGuard
5. VXLAN (depends on underlay)
...
255. Bridge (depends on slave interfaces)
```

#### 5. **Container Isolation**
- Uses **Docker containers** to isolate network namespaces
- FRR runs in containers for multi-router simulation
- Interfaces can be attached to specific containers or host netns

#### 6. **Context-Based Architecture**
Uses Go context for dependency injection:
```go
ctx = SetDockerCliInCtx(ctx, dockerClient)
ctx = SetServiceNameInCtx(ctx, serviceName)
ctx = SetStatefulDirInCtx(ctx, statefulDir)
```

#### 7. **Stateful Operation**
- Maintains state in `.go-reconciler-state/` directory
- Allows tracking of managed resources
- Enables idempotent operations

#### 8. **Type Safety with Go**
- Strongly typed configuration structures
- Compile-time checks for config validity
- YAML/JSON deserialization into Go structs

#### 9. **Netlink Direct Manipulation**
- Uses **vishvananda/netlink** library for direct kernel interaction
- No shell commands for network operations (clean, fast, reliable)

#### 10. **Three-Layer Separation**

| Layer | Responsibility | Technology |
|-------|---------------|------------|
| **Control Plane** | Routing protocols | FRR (vtysh) |
| **Data Plane** | Interfaces, tunnels | netlink, WireGuard |
| **Container Plane** | Isolation, namespaces | Docker |

### Example Flow: Creating a WireGuard Tunnel

1. **User defines in YAML**:
```yaml
dataplane:
  wireguard:
    - name: wg0
      privatekey: "..."
      peers: [...]
```

2. **Parsed into** `WireGuardConfig` struct

3. **Reconciliation**:
   - `DetectChanges()` checks if `wg0` exists
   - If not → adds to `AddedResources`
   - If exists → compares keys, peers, IPs → generates `ChangeSet`

4. **Application**:
   - `Create()` → creates netlink wireguard interface
   - Sets private key via wgctrl
   - Configures peers
   - Assigns IP addresses

5. **Verification**:
   - Next reconciliation loop confirms state matches spec

### CLI Commands

```bash
# Apply configuration
netapply up --service-name exp1 --node testnode --config topology.yaml

# Tear down
netapply down --service-name exp1

# Serve as local configurator (HTTP API)
netapply serve-local --bind-unix-socket /tmp/netapply.sock
```

## Why This Design?

✅ **Reproducible** - Same YAML = Same network topology  
✅ **Testable** - Easy to create/destroy complex network scenarios  
✅ **Educational** - Learn BGP/OSPF/VXLAN without physical hardware  
✅ **Version-controlled** - Network configs in Git  
✅ **Idempotent** - Safe to re-apply configurations  
✅ **Modular** - Easy to add new interface types or protocols

This is an excellent tool for network engineers, students, and researchers who need to experiment with complex routing scenarios without physical equipment!
