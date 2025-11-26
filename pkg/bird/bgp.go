package bird

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func testLinePattern(line []string, pattern []string) bool {
	n := len(pattern)
	if len(line) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if pattern[i] == patternWildCard {
			continue
		} else if pattern[i] == patternAnySequence {
			return true
		} else if line[i] != pattern[i] {
			return false
		}
	}
	return true
}

func extractNumberFromName(name string) int {
	re := regexp.MustCompile(`\d+`)
	matches := re.FindStringSubmatch(name)
	if len(matches) == 0 {
		return -1
	}
	n, err := strconv.Atoi(matches[0])
	if err != nil {
		return -1
	}
	return n
}

func trimLiteralStr(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `"`)
	s = strings.TrimSuffix(s, `;`)
	s = strings.TrimSuffix(s, `"`)
	return s
}

func normalizeLinkLocal(s string, ifname string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "fe80::") {
		idx := strings.Index(s, "%")
		if idx == -1 {
			return s + "%" + ifname
		}
	}
	return s
}

func quoteLiteralStr(s string) string {
	return `"` + s + `"`
}

func appendSemiColon(s string) string {
	return s + ";"
}

func truePtr() *bool {
	t := true
	return &t
}

func FromFile(filename string) (*BGPProtocol, error) {
	lines, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := new(BGPProtocol)

	for _, line := range strings.Split(string(lines), "\n") {
		trimmedLine := strings.TrimSpace(line)
		lineWords := strings.Fields(trimmedLine)
		if testLinePattern(
			lineWords,
			[]string{"protocol", "bgp", patternAnySequence},
		) {
			if len(lineWords) >= 3 {
				result.Name = lineWords[2]
				if testLinePattern(lineWords[3:], []string{"from", patternAnySequence}) {
					if len(lineWords) >= 5 {
						tpl := lineWords[4]
						result.Template = &tpl
					}
				}
			}
		} else if testLinePattern(lineWords, []string{"interface", patternAnySequence}) {
			if len(lineWords) >= 2 {
				ifname := lineWords[1]
				ifname = trimLiteralStr(ifname)
				result.Interface = &ifname
			}
		} else if testLinePattern(lineWords, []string{"local", patternAnySequence}) {
			if len(lineWords) >= 2 {
				localAddr := lineWords[1]
				result.LocalAddress = &localAddr
				if len(lineWords) >= 4 && testLinePattern(lineWords[2:], []string{"as", patternAnySequence}) {
					localASN := lineWords[3]
					localASN = trimLiteralStr(localASN)
					result.LocalASN = &localASN
				}
			}
		} else if testLinePattern(lineWords, []string{"neighbor", patternAnySequence}) {
			if len(lineWords) >= 2 {
				peerAddr := lineWords[1]
				peerAddr = trimLiteralStr(peerAddr)
				result.PeerAddress = &peerAddr
				if len(lineWords) >= 4 && testLinePattern(lineWords[2:], []string{"as", patternAnySequence}) {
					peerASN := lineWords[3]
					peerASN = trimLiteralStr(peerASN)
					result.PeerASN = &peerASN
					if len(lineWords) >= 5 {
						peerType := trimLiteralStr(lineWords[4])
						if peerType == "external" {
							result.PeerExternal = truePtr()
						} else if peerType == "internal" {
							result.PeerInternal = truePtr()
						}
					}
				} else if len(lineWords) >= 3 {
					peerType := trimLiteralStr(lineWords[2])
					if peerType == "external" {
						result.PeerExternal = truePtr()
					} else if peerType == "internal" {
						result.PeerInternal = truePtr()
					}
				}
			}
		}
	}

	if result.Interface != nil {
		if result.LocalAddress != nil {
			localAddr := normalizeLinkLocal(*result.LocalAddress, *result.Interface)
			result.LocalAddress = &localAddr
		}
		if result.PeerAddress != nil {
			peerAddr := normalizeLinkLocal(*result.PeerAddress, *result.Interface)
			result.PeerAddress = &peerAddr
		}
	}

	return result, nil
}

func FromDirectory(dir string) ([]BGPProtocol, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	result := make([]BGPProtocol, 0)
	for _, fileent := range files {
		if fileent.IsDir() {
			continue
		}
		if strings.HasSuffix(fileent.Name(), ".conf") {
			cfg, err := FromFile(filepath.Join(dir, fileent.Name()))
			if err != nil {
				return nil, fmt.Errorf("failed to parse file %s: %w", fileent.Name(), err)
			}
			result = append(result, *cfg)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return extractNumberFromName(result[i].Name) < extractNumberFromName(result[j].Name)
	})
	return result, nil
}

type BGPProtoList []BGPProtocol

func (proto *BGPProtocol) ToConfig() (string, error) {
	lines := make([]string, 0)

	if proto.Name == "" {
		return "", fmt.Errorf("protocol name is required")
	}
	protoLine := []string{"protocol", "bgp", proto.Name}
	if proto.Template != nil {
		protoLine = append(protoLine, "from", *proto.Template)
	}
	protoLine = append(protoLine, "{")

	lines = append(lines, strings.Join(protoLine, " "))

	if proto.Interface != nil {
		ifaceLine := []string{"interface", quoteLiteralStr(*proto.Interface)}
		lines = append(lines, "    "+appendSemiColon(strings.Join(ifaceLine, " ")))
	}

	if proto.LocalAddress != nil {
		localAddrLine := []string{"local", *proto.LocalAddress}
		if proto.LocalASN != nil {
			localAddrLine = append(localAddrLine, "as", *proto.LocalASN)
		}
		lines = append(lines, "    "+appendSemiColon(strings.Join(localAddrLine, " ")))
	}

	if proto.PeerAddress != nil {
		peerAddrLine := []string{"neighbor", *proto.PeerAddress}
		if proto.PeerASN != nil {
			peerAddrLine = append(peerAddrLine, "as", *proto.PeerASN)
			if proto.PeerExternal != nil && *proto.PeerExternal {
				peerAddrLine = append(peerAddrLine, "external")
			} else if proto.PeerInternal != nil && *proto.PeerInternal {
				peerAddrLine = append(peerAddrLine, "internal")
			}
		} else if proto.PeerExternal != nil && *proto.PeerExternal {
			peerAddrLine = append(peerAddrLine, "external")
		} else if proto.PeerInternal != nil && *proto.PeerInternal {
			peerAddrLine = append(peerAddrLine, "internal")
		}
		lines = append(lines, "    "+appendSemiColon(strings.Join(peerAddrLine, " ")))
	}

	lines = append(lines, "}")

	return strings.Join(lines, "\n"), nil
}

func (protoList BGPProtoList) ToConfigs(dir string) error {
	os.MkdirAll(dir, 0755)
	for _, proto := range protoList {
		protoName := proto.Name
		fileBaseName := fmt.Sprintf("%s.conf", protoName)
		filePath := filepath.Join(dir, fileBaseName)
		config, err := proto.ToConfig()
		if err != nil {
			return fmt.Errorf("failed to generate config for protocol %s: %w", protoName, err)
		}
		err = os.WriteFile(filePath, []byte(config), 0644)
		if err != nil {
			return fmt.Errorf("failed to write config to file %s: %w", filePath, err)
		}
	}
	return nil
}

func (proto *BGPProtocol) SetNodeAndResourceID(nodeName string) error {
	if nodeName == "" {
		return fmt.Errorf("node name is required")
	}
	if proto.Node == nil || *proto.Node == "" {
		proto.Node = pkgutils.StringPtr(nodeName)
	}

	if proto.ResourceID == nil || *proto.ResourceID == "" {
		if proto.Name == "" {
			return fmt.Errorf("protocol name is required")
		}
		proto.ResourceID = pkgutils.StringPtr(fmt.Sprintf("%s-%s", nodeName, proto.Name))
	}

	return nil
}

func (proto *BGPProtocol) GetResourceID() (string, error) {
	if proto.ResourceID == nil || *proto.ResourceID == "" {
		return "", fmt.Errorf("resource id is not set")
	}
	return *proto.ResourceID, nil
}

func (proto *BGPProtocol) ToBaseName() string {
	return fmt.Sprintf("%s.conf", proto.Name)
}

func (proto *BGPProtocol) ToFilePath(ctx context.Context) (string, error) {
	baseName := proto.ToBaseName()

	// Note: better not to use "" as current directory, it might be confusing.
	// use "." instead.

	directory := proto.ConfigDirectory
	if directory == "" {
		dirFromCtx, err := pkgutils.BirdBGPConfigDirFromCtx(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get bird bgp config directory from context either: %w", err)
		}
		return filepath.Join(dirFromCtx, baseName), nil
	}
	return filepath.Join(directory, baseName), nil
}
