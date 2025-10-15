package route

import (
	"net"
)

type RouteScope string

const (
	RouteScopeUniverse RouteScope = "universe"
	RouteScopeSite     RouteScope = "site"
	RouteScopeLink     RouteScope = "link"
	RouteScopeHost     RouteScope = "host"
	RouteScopeNowhere  RouteScope = "nowhere"
)

type RouteProtocol string

const (
	RouteProtocolStatic RouteProtocol = "static"
)

type RouteConfig struct {
	TableId *uint32 `yaml:"table_id,omitempty" json:"table_id,omitempty"`

	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`

	// Destination is a CIDR string
	Destionation string `yaml:"destionation" json:"destionation"`

	NextHop string `yaml:"next_hop,omitempty" json:"next_hop,omitempty"`

	NextHopInterface *string `yaml:"next_hop_interface,omitempty" json:"next_hop_interface,omitempty"`

	InboundInterface *string `yaml:"inbound_interface,omitempty" json:"inbound_interface,omitempty"`

	// Source address to prefer for the route
	Source *string `yaml:"source,omitempty" json:"source,omitempty"`

	// See https://pkg.go.dev/github.com/vishvananda/netlink#Scope
	// If omitted, it use RouteScopeUniverse for default
	Scope *RouteScope `yaml:"scope,omitempty" json:"scope,omitempty"`

	Priority *int `yaml:"priority,omitempty" json:"priority,omitempty"`
	Family   *int `yaml:"family,omitempty" json:"family,omitempty"`

	// See /etc/iproute2/rt_protos
	// It indicates who installed the route to the routing table, currently,
	// only 'static' is supported since this program is expected to be invoked (or indirectly invoked) by the sysadmin.
	// And when reconciling, we use this field to differentiate it from the others (such as those installed by BGP or OSPF)
	Protocol *RouteProtocol `yaml:"protocol,omitempty" json:"protocol,omitempty"`
}

type RouteConfigurationList []RouteConfig

type RouteObjectChangeSet struct {
	Spec *RouteConfig

	ShouldChangeNextHop  *net.IP
	ShouldChangeSource   *net.IP
	ShouldChangeDev      *string
	ShouldChangeIIface   *string
	ShouldChangePriority *int
}
