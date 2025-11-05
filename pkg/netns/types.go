package netns

import (
	"context"
)

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
