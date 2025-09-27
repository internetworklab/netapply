package ospf

import "fmt"

func (interfaceConfig *OSPFInterfaceConfig) ToCLICommands(ospfConfig *OSPFConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("interface %s vrf %s", interfaceConfig.Name, ospfConfig.VRF))

	cmds = append(cmds, fmt.Sprintf("ip ospf area %s", interfaceConfig.Area))

	if interfaceConfig.Passive != nil && *interfaceConfig.Passive {
		cmds = append(cmds, "ip ospf passive")
	} else if interfaceConfig.Network != nil {
		cmds = append(cmds, fmt.Sprintf("ip ospf network %s", *interfaceConfig.Network))
	}

	cmds = append(cmds, "exit")

	return cmds
}

func (ospfConf *OSPFConfig) ToCLICommands() []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("router ospf vrf %s", ospfConf.VRF))
	cmds = append(cmds, fmt.Sprintf("ospf router-id %s", ospfConf.RouterID))
	cmds = append(cmds, "exit")

	for _, interfaceConfig := range ospfConf.Interfaces {
		cmds = append(cmds, interfaceConfig.ToCLICommands(ospfConf)...)
	}

	return cmds
}
