package stub

type StubInterfaceCanceller struct {
	ContainerName *string
	InterfaceName string
}

type StubNetlinkInterface interface {
	GetType() string
	GetContainerName() *string
	GetInterfaceName() string
}
