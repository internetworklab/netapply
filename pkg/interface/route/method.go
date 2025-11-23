package route

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"strings"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const ResourceTypeRoute = "route"

func (scope RouteScope) ToUInt8() netlink.Scope {
	switch scope {
	case RouteScopeUniverse:
		return unix.RT_SCOPE_UNIVERSE
	case RouteScopeSite:
		return unix.RT_SCOPE_SITE
	case RouteScopeLink:
		return unix.RT_SCOPE_LINK
	case RouteScopeHost:
		return unix.RT_SCOPE_HOST
	case RouteScopeNowhere:
		return unix.RT_SCOPE_NOWHERE
	default:
		return unix.RT_SCOPE_UNIVERSE
	}
}

// We use net.IPNet rather than string because we want a unique representation for the same route,
// for example, 10.2.3.4/32 and 10.2.3.4 should be treated as the same destination.
// And also we wanna reuse this function in the indexing procedure of RouteConfigurationList
func getResourceKey(table *uint32, destIPNet net.IPNet) string {
	if table == nil || *table == 0 {
		return destIPNet.String()
	}
	return fmt.Sprintf("%s (table %d)", destIPNet.String(), *table)
}

const InvalidDestination = "(invalid)"

func (r *RouteConfig) GetInterfaceName() string {
	_, ipNet, err := net.ParseCIDR(r.Destionation)
	if err != nil {
		// deal with a.b.c.d or A:B::C:D notation (i.e. no VLSM, so we treat it as full mask)
		ip := net.ParseIP(r.Destionation)
		if ip == nil {
			return InvalidDestination
		}
		fullMaskNet := pkgutils.WithFullMaskIPNet(ip)
		if fullMaskNet == nil {
			return InvalidDestination
		}
		return getResourceKey(r.TableId, *fullMaskNet)
	}
	// Deal with normal a.b.c.d/x or A:B::C:D/y CIDR notation
	return getResourceKey(r.TableId, *ipNet)
}

func (r *RouteConfig) GetContainerName() *string {
	return r.ContainerName
}

// If it returns nil, it means that the table(or vrf) is not created yet
func (r *RouteConfig) GetTableId(ctx context.Context) uint32 {
	if r.TableId != nil {
		return *r.TableId
	}
	return 0
}

func retrieveRouteObject(
	ctx context.Context,
	res *RouteConfig,
	destIPNet net.IPNet,
	proto netlink.RouteProtocol,
) (*netlink.Route, error) {
	type result struct {
		Route *netlink.Route
	}
	res := new(result)

	err := pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {

		routes, err := handle.RouteGet(destIPNet.IP)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return fmt.Errorf("failed to get routes: %w", err)
			}
		}

		for _, nlroute := range routes {
			if nlroute.Protocol != proto {
				continue
			}

			if tableId != uint32(nlroute.Table) {
				continue
			}

			if nlroute.Dst.String() == destIPNet.String() {
				res.Route = &nlroute
				break
			}
		}

		return nil
	})

	return res.Route, err
}

func (r *RouteConfig) RetrieveRouteObject(ctx context.Context) (*netlink.Route, error) {
	tableId := r.GetTableId(ctx)

	_, destIPNet, err := net.ParseCIDR(r.Destionation)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	protoExpected := RouteProtocolStatic.ToInt()
	if r.Protocol != nil {
		protoExpected = r.Protocol.ToInt()
	}

	netnsInfo, err := r.GetNetNsInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary netns info: %w", err)
	}

	return retrieveRouteObject(ctx, netnsInfo, tableId, *destIPNet, protoExpected)
}

func (r *RouteConfig) CheckExist(ctx context.Context) (bool, error) {
	routeObj, err := r.RetrieveRouteObject(ctx)
	return routeObj != nil, err
}

func (protocol RouteProtocol) ToInt() netlink.RouteProtocol {
	checkFiles := []string{
		"/etc/iproute2/rt_protos", // /etc/xyz always takes precedence over /usr/share/xyz since the later is (mostly) vendor-shipped, and the former reflects the intention of the sysadmin.
		"/usr/share/iproute2/rt_protos",
	}
	for _, fname := range checkFiles {
		fcontentsBytes, err := os.ReadFile(fname)
		if err != nil {
			log.Printf("Warining, when reading file %s: %v", fname, err)
			continue
		}

		fcontents := string(fcontentsBytes)
		lines := strings.Split(fcontents, "\n")
		for _, line := range lines {
			tline := strings.TrimSpace(line)
			if tline == "" {
				continue
			}
			if strings.HasPrefix(tline, "#") {
				continue
			}
			parts := strings.Split(tline, " ")
			if len(parts) < 2 {
				continue
			}

			protocolId, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}

			for i := 1; i < len(parts); i++ {
				if parts[i] == string(protocol) {
					return netlink.RouteProtocol(protocolId)
				}
			}
		}
	}

	// In most cases, 0 means unspecified or default value
	return netlink.RouteProtocol(0)
}

func (r *RouteConfig) GetType() string {
	return ResourceTypeRoute
}

func (r *RouteConfig) Create(ctx context.Context) error {
	netnsInfo, err := r.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get primary netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		rtObj := new(netlink.Route)

		rtObj.Table = int(r.GetTableId(ctx))

		rtObj.Protocol = RouteProtocolStatic.ToInt()
		if r.Protocol != nil {
			rtObj.Protocol = r.Protocol.ToInt()
		}

		if r.InboundInterface != nil {
			link, err := handle.LinkByName(*r.InboundInterface)
			if err != nil {
				return fmt.Errorf("failed to get inbound interface: %w", err)
			}
			rtObj.LinkIndex = link.Attrs().Index
		}

		if r.NextHopInterface != nil {
			link, err := handle.LinkByName(*r.NextHopInterface)
			if err != nil {
				return fmt.Errorf("failed to get next hop interface: %w", err)
			}
			rtObj.LinkIndex = link.Attrs().Index
		}

		if r.Scope != nil {
			rtObj.Scope = r.Scope.ToUInt8()
		}

		if r.Family != nil {
			rtObj.Family = *r.Family
		}

		if r.Priority != nil {
			rtObj.Priority = *r.Priority
		}

		_, destIPNet, err := net.ParseCIDR(r.Destionation)
		if err != nil {
			return fmt.Errorf("failed to parse destination: %w", err)
		}

		rtObj.Dst = destIPNet

		if r.NextHop == "" {
			return fmt.Errorf("next hop is not set")
		}

		nextHopIP := net.ParseIP(r.NextHop)
		if nextHopIP == nil {
			return fmt.Errorf("failed to parse next hop: %s", r.NextHop)
		}

		rtObj.Gw = nextHopIP

		if r.Source != nil && *r.Source != "" {
			srcIP := net.ParseIP(*r.Source)
			if srcIP == nil {
				return fmt.Errorf("failed to parse source: %s", *r.Source)
			}

			rtObj.Src = srcIP
		}

		err = handle.RouteAdd(rtObj)
		if err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create route: %w", err)
	}

	return nil
}

func (r *RouteObjectChangeSet) GetContainerName() *string {
	return r.Spec.GetContainerName()
}

func (r *RouteObjectChangeSet) GetInterfaceName() string {
	return r.Spec.GetInterfaceName()
}

func (r *RouteObjectChangeSet) HasUpdates() bool {
	if r == nil {
		return false
	}

	return r.ShouldChangeNextHop != nil ||
		r.ShouldChangeSource != nil ||
		r.ShouldChangeDev != nil ||
		r.ShouldChangeIIface != nil ||
		r.ShouldChangePriority != nil
}

func (r *RouteObjectChangeSet) Apply(ctx context.Context) error {

	if !r.HasUpdates() {
		return nil
	}

	netnsInfo, err := r.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {

		rtObj, err := r.Spec.RetrieveRouteObject(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve route object: %w", err)
		}

		if r.ShouldChangeNextHop != nil {
			rtObj.Gw = *r.ShouldChangeNextHop
		}

		if r.ShouldChangeSource != nil {
			rtObj.Src = *r.ShouldChangeSource
		}

		if r.ShouldChangeDev != nil {
			link, err := handle.LinkByName(*r.ShouldChangeDev)
			if err != nil {
				return fmt.Errorf("failed to get link by name: %w", err)
			}
			rtObj.LinkIndex = link.Attrs().Index
		}

		if r.ShouldChangeIIface != nil {
			link, err := handle.LinkByName(*r.ShouldChangeIIface)
			if err != nil {
				return fmt.Errorf("failed to get link by name: %w", err)
			}
			rtObj.ILinkIndex = link.Attrs().Index
		}

		if r.ShouldChangePriority != nil {
			rtObj.Priority = *r.ShouldChangePriority
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to apply route object change set: %w", err)
	}

	return nil
}

func (r *RouteObjectChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (r *RouteConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(RouteObjectChangeSet)
	changeSet.Spec = r
	netnsInfo, err := r.GetNetNsInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		rtObj, err := r.RetrieveRouteObject(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve route object: %w", err)
		}

		if rtObj.Gw.String() != r.NextHop {
			desiredNH := net.ParseIP(r.NextHop)
			if desiredNH == nil {
				return fmt.Errorf("failed to parse next hop: %s", r.NextHop)
			}
			changeSet.ShouldChangeNextHop = &desiredNH
		}

		if r.Source != nil && *r.Source != "" && rtObj.Src.String() != *r.Source {
			desiredSrc := net.ParseIP(*r.Source)
			if desiredSrc == nil {
				return fmt.Errorf("failed to parse source: %s", *r.Source)
			}
			changeSet.ShouldChangeSource = &desiredSrc
		}

		if r.NextHopInterface != nil && *r.NextHopInterface != "" {
			link, err := handle.LinkByName(*r.NextHopInterface)
			if err != nil {
				return fmt.Errorf("failed to get link by name: %w", err)
			}
			if link.Attrs().Index != rtObj.LinkIndex {
				changeSet.ShouldChangeDev = r.NextHopInterface
			}
		}

		if r.InboundInterface != nil && *r.InboundInterface != "" {
			link, err := handle.LinkByName(*r.InboundInterface)
			if err != nil {
				return fmt.Errorf("failed to get link by name: %w", err)
			}
			if link.Attrs().Index != rtObj.ILinkIndex {
				changeSet.ShouldChangeIIface = r.InboundInterface
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	return changeSet, nil
}

func (r *RouteResourceCanceller) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (r *RouteResourceCanceller) Cancel(ctx context.Context) error {
	netnsInfo, err := r.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {

		routeObj, err := retrieveRouteObject(ctx, netnsInfo, r.TableId, r.Destination, RouteProtocolStatic.ToInt())
		if err != nil {
			// Can't retrieve the route object, presumably it's already deleted
			return nil
		}

		err = handle.RouteDel(routeObj)
		if err != nil {
			// It it's successfully retrieved but failed to delete, it should be considered as an error
			return fmt.Errorf("failed to delete route: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to cancel route: %w", err)
	}

	return nil
}

func (r *RouteResourceCanceller) GetInterfaceName() string {
	return getResourceKey(&r.TableId, r.Destination)
}

func (r *RouteResourceCanceller) GetType() string {
	return ResourceTypeRoute
}

func (r *RouteConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if r == nil {
		return nil
	}
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, routeCfg := range r.Routes {
		if routeCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &routeCfg)
	}
	return provisioners
}

func (r *RouteObjectChangeSet) GetType() string {
	return ResourceTypeRoute
}

func (r *RouteConfigurationList) GetType() string {
	return ResourceTypeRoute
}

func (r *RouteConfigurationList) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {
	// todo
	return nil, nil
}

func (r *RouteConfig) IsSoftDeleted() bool {
	return r.Deleted
}

func (r *RouteConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}
