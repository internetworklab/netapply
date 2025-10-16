package stub

type StubInterfaceCanceller struct {
	ContainerName *string
	InterfaceName string
	Type string
}

type StubNetlinkInterface interface {
	GetType() string
	GetContainerName() *string
	GetInterfaceName() string
}
