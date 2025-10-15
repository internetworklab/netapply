package route

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"strings"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

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

func (r *RouteConfig) GetInterfaceName() string {
	if r.TableId != nil && *r.TableId != 0 {
		return fmt.Sprintf("%s (table %d)", r.Destionation, *r.TableId)
	}
	return r.Destionation
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

func (r *RouteConfig) RetrieveRouteObject(ctx context.Context) (*netlink.Route, error) {
	tableId := r.GetTableId(ctx)

	type result struct {
		Route *netlink.Route
	}
	res := new(result)

	err := pkgdocker.WithNsHandleSafe(ctx, r.ContainerName, func(handle *netlink.Handle) error {
		destIP, destIPNet, err := net.ParseCIDR(r.Destionation)
		if err != nil {
			return fmt.Errorf("failed to parse destination: %w", err)
		}
		routes, err := handle.RouteGet(destIP)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return fmt.Errorf("failed to get routes: %w", err)
			}
		}

		protoExpected := RouteProtocolStatic.ToInt()
		if r.Protocol != nil {
			protoExpected = r.Protocol.ToInt()
		}
		for _, nlroute := range routes {
			if nlroute.Protocol != protoExpected {
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
	return "route"
}

func (r *RouteConfig) Create(ctx context.Context) error {
	return pkgdocker.WithNsHandleSafe(ctx, r.ContainerName, func(handle *netlink.Handle) error {
		route := new(netlink.Route)

		route.Table = int(r.GetTableId(ctx))

		route.Protocol = RouteProtocolStatic.ToInt()
		if r.Protocol != nil {
			route.Protocol = r.Protocol.ToInt()
		}

		if r.InboundInterface != nil {
			link, err := handle.LinkByName(*r.InboundInterface)
			if err != nil {
				return fmt.Errorf("failed to get inbound interface: %w", err)
			}
			route.LinkIndex = link.Attrs().Index
		}

		if r.NextHopInterface != nil {
			link, err := handle.LinkByName(*r.NextHopInterface)
			if err != nil {
				return fmt.Errorf("failed to get next hop interface: %w", err)
			}
			route.LinkIndex = link.Attrs().Index
		}

		if r.Scope != nil {
			route.Scope = r.Scope.ToUInt8()
		}

		if r.Family != nil {
			route.Family = *r.Family
		}

		if r.Priority != nil {
			route.Priority = *r.Priority
		}

		_, destIPNet, err := net.ParseCIDR(r.Destionation)
		if err != nil {
			return fmt.Errorf("failed to parse destination: %w", err)
		}

		route.Dst = destIPNet

		if r.NextHop == "" {
			return fmt.Errorf("next hop is not set")
		}

		nextHopIP := net.ParseIP(r.NextHop)
		if nextHopIP == nil {
			return fmt.Errorf("failed to parse next hop: %s", r.NextHop)
		}

		route.Gw = nextHopIP

		if r.Source != nil && *r.Source != "" {
			srcIP := net.ParseIP(*r.Source)
			if srcIP == nil {
				return fmt.Errorf("failed to parse source: %s", *r.Source)
			}

			route.Src = srcIP
		}

		err = handle.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
		return nil
	})
}
