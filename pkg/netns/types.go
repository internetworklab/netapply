package netns

import (
	"context"
)

// A NetNsInfo is different from a NsHandle object in vishvananda/netns package, the later is a handle that
// usually points to a opened file descriptor (hence the name 'handle'), whilst the former is simply a struct
// that describes something.
// To say, a NsHandle is more or less a file descriptor that points to a opened file handle of some process.
type NetNsInfo struct {
	Pid       *int
	NetNsPath *string
}

// A resource is said to be netns-aware if it can provide its netns info.
// By relying on this interface, developers can manipulate those netns-aware resources
// in a vendor-neutral manner.
// If netnsInfo is nil, the caller should treat the resource as host-netns-only.
type NetNsAwareResource interface {
	GetNetNsInfo(ctx context.Context) (netnsInfo *NetNsInfo, err error)
}

// This interface are intended for multi-netns reconcilable resourcelist.
// If netnsInfos is empty, the caller should treat the resourcelist as host-netns-only.
type MultiNetnsResource interface {
	GetNetNsInfos(ctx context.Context) (netnsInfos []NetNsInfo, err error)
}
