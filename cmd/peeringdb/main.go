package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"
)

type BGPProtocol struct {
	Name         string  `yaml:"name" json:"name"`
	Template     *string `yaml:"template,omitempty" json:"template,omitempty"`
	Interface    *string `yaml:"interface,omitempty" json:"interface,omitempty"`
	LocalAddress *string `yaml:"local_address,omitempty" json:"local_address,omitempty"`
	PeerAddress  *string `yaml:"peer_address,omitempty" json:"peer_address,omitempty"`
	LocalASN     *string `yaml:"local_asn,omitempty" json:"local_asn,omitempty"`
	PeerASN      *string `yaml:"peer_asn,omitempty" json:"peer_asn,omitempty"`
	PeerExternal *bool   `yaml:"peer_external,omitempty" json:"peer_external,omitempty"`
	PeerInternal *bool   `yaml:"peer_internal,omitempty" json:"peer_internal,omitempty"`
}

const patternWildCard = "*"
const patternAnySequence = "**"

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
		} else if proto.PeerExternal != nil {
			peerAddrLine = append(peerAddrLine, "external")
		} else if proto.PeerInternal != nil {
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

var CLI struct {
	FromDirectory string `help:"Directory to read from." type:"path"`
	FromYAML      string `help:"YAML file to read from." type:"path"`
	ToDirectory   string `help:"Directory to write to." type:"path"`
}

func main() {
	kong.Parse(&CLI)
	var protoList BGPProtoList
	var err error
	if CLI.FromDirectory != "" {
		protoList, err = FromDirectory(CLI.FromDirectory)
		if err != nil {
			log.Fatalf("failed to read from directory %s: %v", CLI.FromDirectory, err)
		}
	} else if CLI.FromYAML != "" {
		f, err := os.Open(CLI.FromYAML)
		if err != nil {
			log.Fatalf("failed to open YAML file %s: %v", CLI.FromYAML, err)
		}
		defer f.Close()
		yaml.NewDecoder(f).Decode(&protoList)
	}

	if CLI.ToDirectory != "" {
		if CLI.ToDirectory != "" {
			err = protoList.ToConfigs(CLI.ToDirectory)
			if err != nil {
				log.Fatalf("failed to write to directory %s: %v", CLI.ToDirectory, err)
			}
		}
	} else {
		encoder := yaml.NewEncoder(os.Stdout)
		encoder.SetIndent(2)
		err = encoder.Encode(protoList)
		if err != nil {
			log.Fatalf("failed to encode YAML: %v", err)
		}
	}
}
