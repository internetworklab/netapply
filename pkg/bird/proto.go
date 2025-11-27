package bird

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func SplitBy(seq []byte) bufio.SplitFunc {
	splitFunc := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, seq); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
	return splitFunc
}

type Line struct {
	LineIdx      int           `json:"line_idx"`
	LineGroupIdx int           `json:"line_group_idx"`
	Raw          string        `json:"raw"`
	Metadata     LineMetadata  `json:"metadata"`
	Meaning      *ReplyMeaning `json:"meaning"`
	Indent       int           `json:"indent"`
	Content      string        `json:"content"`
	TrimmedLine  string        `json:"trimmed_line"`
}

const maxTokenSize = 1024 * 1024

type RawMessages struct {
	Lines  []Line  `json:"lines"`
	Blocks []Block `json:"blocks"`
}

type LineMetadata struct {
	HasGroupSeperator bool   `json:"has_group_seperator"`
	Continuation      bool   `json:"continuation"`
	EndOfReply        bool   `json:"end_of_reply"`
	ContentOffset     int    `json:"content_offset"`
	Code              string `json:"code"`
}

type ReplyMeaning string

const (
	ReplySuccess      ReplyMeaning = "success"
	ReplyTableHeader  ReplyMeaning = "table_header"
	ReplyTableEntries ReplyMeaning = "table_entry"
	ReplyRuntimeError ReplyMeaning = "runtime_error"
	ReplySyntaxError  ReplyMeaning = "syntax_error"
)

func (r *ReplyMeaning) String() string {
	if r == nil {
		return "(unknown)"
	}
	return string(*r)
}

func ReplyMeaningFromCode(code string) (replyMeaning *ReplyMeaning) {
	replyMeaning = new(ReplyMeaning)
	if len(code) > 0 {
		switch code[0:1] {
		case "0":
			*replyMeaning = ReplySuccess
		case "2":
			*replyMeaning = ReplyTableHeader
		case "1":
			*replyMeaning = ReplyTableEntries
		case "8":
			*replyMeaning = ReplyRuntimeError
		case "9":
			*replyMeaning = ReplySyntaxError
		default:
			return nil
		}
		return replyMeaning
	}
	return nil
}

type Block struct {
	BlockIndex int    `json:"block_index"`
	Lines      []Line `json:"lines"`
}

type ChannelRoutesStat struct {
	Imported  int `json:"imported"`
	Filtered  int `json:"filtered"`
	Exported  int `json:"exported"`
	Preferred int `json:"preferred"`
}

type ChannelRouteChangesStatEntry struct {
	Received *int `json:"received,omitempty"`
	Rejected *int `json:"rejected,omitempty"`
	Filtered *int `json:"filtered,omitempty"`
	Ignored  *int `json:"ignored,omitempty"`
	Accepted *int `json:"accepted,omitempty"`
}

type ChannelRouteChangesStat struct {
	ImportUpdates   *ChannelRouteChangesStatEntry `json:"import_updates,omitempty"`
	ImportWithdraws *ChannelRouteChangesStatEntry `json:"import_withdraws,omitempty"`
	ExportUpdates   *ChannelRouteChangesStatEntry `json:"export_updates,omitempty"`
	ExportWithdraws *ChannelRouteChangesStatEntry `json:"export_withdraws,omitempty"`
}

type BGPCapabilitiesInfo []string

type ChannelInfo struct {
	Name             string                   `json:"name"`
	State            string                   `json:"state"`
	Preference       *int                     `json:"preference,omitempty"`
	InputFilter      string                   `json:"input_filter"`
	OutputFilter     string                   `json:"output_filter"`
	RoutesStat       *ChannelRoutesStat       `json:"routes_stat,omitempty"`
	RouteChangesStat *ChannelRouteChangesStat `json:"route_changes_stat,omitempty"`
	BGPNextHop       *string                  `json:"bgp_next_hop,omitempty"`
}

type BGPProtoBasics struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Table string `json:"table"`
	State string `json:"state"`
	Since string `json:"since"`
	Info  string `json:"info"`
}

type BGPProtoInfo struct {
	Basics *BGPProtoBasics `json:"basics,omitempty"`

	VRF             *string `json:"vrf,omitempty"`
	BGPState        *string `json:"bgp_state,omitempty"`
	NeighborAddress *string `json:"neighbor_address,omitempty"`
	NeighborAS      *string `json:"neighbor_as,omitempty"`
	LocalAS         *string `json:"local_as,omitempty"`
	NeighborID      *string `json:"neighbor_id,omitempty"`
	Session         *string `json:"session,omitempty"`
	SourceAddress   *string `json:"source_address,omitempty"`
	HoldTimer       *string `json:"hold_timer,omitempty"`
	KeepaliveTimer  *string `json:"keepalive_timer,omitempty"`
	SendHoldTimer   *string `json:"send_hold_timer,omitempty"`

	LocalCapabilities    BGPCapabilitiesInfo    `json:"local_capabilities,omitempty"`
	NeighborCapabilities BGPCapabilitiesInfo    `json:"neighbor_capabilities,omitempty"`
	Channels             map[string]ChannelInfo `json:"channels,omitempty"`
}

func parseBGPProtoBasics(line string) *BGPProtoBasics {
	result := new(BGPProtoBasics)
	cells := make([]string, 0)
	for _, cell := range strings.Split(line, " ") {
		c := strings.TrimSpace(cell)
		if c == "" {
			continue
		}
		cells = append(cells, c)
	}

	if len(cells) > 6 {
		cells[4] = cells[4] + " " + cells[5]
		cells[5] = cells[6]
	}

	if len(cells) > 0 {
		result.Name = cells[0]
	}
	if len(cells) > 1 {
		result.Proto = cells[1]
	}
	if len(cells) > 2 {
		result.Table = cells[2]
	}
	if len(cells) > 3 {
		result.State = cells[3]
	}
	if len(cells) > 4 {
		result.Since = cells[4]
	}
	if len(cells) > 5 {
		result.Info = cells[5]
	}
	return result
}

func parseBGPProtoInfo(lines []Line) *BGPProtoInfo {
	summaryTabPattern := regexp.MustCompile(`Name\s+Proto\s+Table\s+State\s+Since\s+Info`)
	if summaryTabPattern.MatchString(lines[0].TrimmedLine) && len(lines) > 1 {
		result := new(BGPProtoInfo)
		result.Channels = make(map[string]ChannelInfo)

		basics := parseBGPProtoBasics(lines[1].TrimmedLine)
		if basics != nil {
			result.Basics = basics
		}

		for _, line := range lines {
			if v := matchPrefix(`^VRF:\s+`, line.TrimmedLine); v != "" {
				result.VRF = &v
			}
			if v := matchPrefix(`^BGP state:\s+`, line.TrimmedLine); v != "" {
				result.BGPState = &v
			}
			if v := matchPrefix(`^Neighbor address:\s+`, line.TrimmedLine); v != "" {
				result.NeighborAddress = &v
			}
			if v := matchPrefix(`^Neighbor AS:\s+`, line.TrimmedLine); v != "" {
				result.NeighborAS = &v
			}
			if v := matchPrefix(`^Local AS:\s+`, line.TrimmedLine); v != "" {
				result.LocalAS = &v
			}
			if v := matchPrefix(`^Neighbor ID:\s+`, line.TrimmedLine); v != "" {
				result.NeighborID = &v
			}
			if v := matchPrefix(`^Session:\s+`, line.TrimmedLine); v != "" {
				result.Session = &v
			}
			if v := matchPrefix(`^Source address:\s+`, line.TrimmedLine); v != "" {
				result.SourceAddress = &v
			}
			if v := matchPrefix(`^Hold timer:\s+`, line.TrimmedLine); v != "" {
				result.HoldTimer = &v
			}
			if v := matchPrefix(`^Keepalive timer:\s+`, line.TrimmedLine); v != "" {
				result.KeepaliveTimer = &v
			}
			if v := matchPrefix(`^Send hold timer:\s+`, line.TrimmedLine); v != "" {
				result.SendHoldTimer = &v
			}
		}

		if lineIdx := findLineIdx(lines, `^Local capabilities`); lineIdx >= 0 {
			localCapabilities := parseBGPCapabilitiesInfo(lines[lineIdx:])
			result.LocalCapabilities = localCapabilities
		}
		if lineIdx := findLineIdx(lines, `^Neighbor capabilities`); lineIdx >= 0 {
			neighborCapabilities := parseBGPCapabilitiesInfo(lines[lineIdx:])
			result.NeighborCapabilities = neighborCapabilities
		}

		if lineIdx := findLineIdx(lines, `^Channel ipv6`); lineIdx >= 0 {
			channelInfo := parseChannel(lines[lineIdx : lineIdx+13])
			if channelInfo != nil {
				result.Channels[channelInfo.Name] = *channelInfo
			}
		}
		if lineIdx := findLineIdx(lines, `^Channel ipv4`); lineIdx >= 0 {
			channelInfo := parseChannel(lines[lineIdx : lineIdx+13])
			if channelInfo != nil {
				result.Channels[channelInfo.Name] = *channelInfo
			}
		}

		return result
	}

	return nil
}

func parseRouteStats(line string) *ChannelRoutesStat {
	result := new(ChannelRoutesStat)
	numMatches := 0

	importedPattern := regexp.MustCompile(`(\d+)\s+imported`)
	if matches := importedPattern.FindStringSubmatch(line); matches != nil {
		imported, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Imported = imported
			numMatches++
		}
	}

	filteredPattern := regexp.MustCompile(`(\d+)\s+filtered`)
	if matches := filteredPattern.FindStringSubmatch(line); matches != nil {
		filtered, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Filtered = filtered
			numMatches++
		}
	}

	exportedPattern := regexp.MustCompile(`(\d+)\s+exported`)
	if matches := exportedPattern.FindStringSubmatch(line); matches != nil {
		exported, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Exported = exported
			numMatches++
		}
	}

	preferredPattern := regexp.MustCompile(`(\d+)\s+preferred`)
	if matches := preferredPattern.FindStringSubmatch(line); matches != nil {
		preferred, err := strconv.Atoi(matches[1])
		if err == nil {
			result.Preferred = preferred
			numMatches++
		}
	}

	if numMatches == 0 {
		return nil
	}

	return result
}

func parseNums(line string) []*int {
	segs := strings.Split(line, " ")
	result := make([]*int, 0)
	for _, seg := range segs {
		word := strings.TrimSpace(seg)
		if word == "" {
			continue
		}
		if x, err := strconv.Atoi(word); err == nil {
			result = append(result, &x)
		} else {
			result = append(result, nil)
		}
	}
	return result
}

func parseRouteChangesStatEntry(importUpdatesLine string) *ChannelRouteChangesStatEntry {
	nums := parseNums(importUpdatesLine)
	if len(nums) == 0 {
		return nil
	}
	updateStats := new(ChannelRouteChangesStatEntry)
	if len(nums) > 0 {
		updateStats.Received = nums[0]
	}
	if len(nums) > 1 {
		updateStats.Rejected = nums[1]
	}
	if len(nums) > 2 {
		updateStats.Filtered = nums[2]
	}
	if len(nums) > 3 {
		updateStats.Ignored = nums[3]
	}
	if len(nums) > 4 {
		updateStats.Accepted = nums[4]
	}
	return updateStats
}

func findLineIdx(lines []Line, pattern string) int {
	patternObj := regexp.MustCompile(pattern)
	for i, line := range lines {
		if patternObj.MatchString(line.TrimmedLine) {
			return i
		}
	}
	return -1
}

func matchPrefix(prefixPattern string, line string) string {
	pattern := regexp.MustCompile(prefixPattern)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 0 {
		match0 := matches[0]
		return strings.TrimSpace(line[len(match0):])
	}
	return ""
}

func parseBGPCapabilitiesInfo(lines []Line) BGPCapabilitiesInfo {
	result := make(BGPCapabilitiesInfo, 0)
	for i := 1; i < len(lines); i++ {
		if lines[i].Indent > lines[0].Indent {
			result = append(result, lines[i].TrimmedLine)
		} else {
			break
		}
	}
	return result
}

func parseChannel(lines []Line) *ChannelInfo {
	channelInfo := new(ChannelInfo)

	for _, lineObj := range lines {
		line := lineObj.TrimmedLine
		if channelName := matchPrefix(`^Channel\s+`, line); channelName != "" {
			channelInfo.Name = channelName
		} else if state := matchPrefix(`^State:\s+`, line); state != "" {
			channelInfo.State = state
		} else if pref := matchPrefix(`^Preference:\s+`, line); pref != "" {
			prefInt, err := strconv.Atoi(pref)
			if err == nil {
				channelInfo.Preference = &prefInt
			}
		} else if inputFilter := matchPrefix(`^Input filter:\s+`, line); inputFilter != "" {
			channelInfo.InputFilter = inputFilter
		} else if outputFilter := matchPrefix(`^Output filter:\s+`, line); outputFilter != "" {
			channelInfo.OutputFilter = outputFilter
		} else if routeStatLine := matchPrefix(`^Routes:\s+`, line); routeStatLine != "" {
			channelInfo.RoutesStat = parseRouteStats(routeStatLine)
		} else if routeChangesStatLine := matchPrefix(`^Route changes:\s+`, line); routeChangesStatLine != "" {
			continue
		} else if importUpdates := matchPrefix(`^Import updates:\s+`, line); importUpdates != "" {
			if entry := parseRouteChangesStatEntry(importUpdates); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ImportUpdates = entry
			}
		} else if importWithdraws := matchPrefix(`^Import withdraws:\s+`, line); importWithdraws != "" {
			if entry := parseRouteChangesStatEntry(importWithdraws); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ImportWithdraws = entry
			}
		} else if exportUpdates := matchPrefix(`^Export updates:\s+`, line); exportUpdates != "" {
			if entry := parseRouteChangesStatEntry(exportUpdates); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ExportUpdates = entry
			}
		} else if exportWithdraws := matchPrefix(`^Export withdraws:\s+`, line); exportWithdraws != "" {
			if entry := parseRouteChangesStatEntry(exportWithdraws); entry != nil {
				if channelInfo.RouteChangesStat == nil {
					channelInfo.RouteChangesStat = new(ChannelRouteChangesStat)
				}
				channelInfo.RouteChangesStat.ExportWithdraws = entry
			}
		} else if bgpNextHop := matchPrefix(`^BGP Next hop:\s+`, line); bgpNextHop != "" {
			channelInfo.BGPNextHop = &bgpNextHop
		}
	}

	return channelInfo
}

func (b *Block) Content() string {
	lines := make([]string, 0)
	for _, line := range b.Lines {
		lines = append(lines, line.Content)
	}
	return strings.Join(lines, "\n")
}

func testForGroupSep(line string) LineMetadata {
	meta := LineMetadata{}
	meta.ContentOffset = 0

	pattern1 := regexp.MustCompile(`^\d{4} `)
	if pattern1.MatchString(line) {
		meta.HasGroupSeperator = true
		meta.EndOfReply = true
		meta.ContentOffset = 5
		meta.Code = line[:4]
	}

	pattern2 := regexp.MustCompile(`^\d{4}-`)
	if pattern2.MatchString(line) {
		meta.HasGroupSeperator = true
		meta.Continuation = true
		meta.ContentOffset = 5
		meta.Code = line[:4]
	}

	return meta
}

func countIndent(line string) int {
	pattern := regexp.MustCompile(`^\s*`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 0 {
		return len(matches[0])
	}
	return 0
}

type BirdBGPProtoInfoParser struct {
	reader io.Reader
}

func NewBirdBGPProtoInfoParser(reader io.Reader) *BirdBGPProtoInfoParser {
	return &BirdBGPProtoInfoParser{
		reader: reader,
	}
}

func (parser *BirdBGPProtoInfoParser) Parse() *BGPProtoInfo {
	msgs := new(RawMessages)
	msgs.Lines = make([]Line, 0)
	numLinesRead := 0

	scanner := bufio.NewScanner(parser.reader)
	scanBuf := make([]byte, maxTokenSize)
	scanner.Buffer(scanBuf, maxTokenSize)
	scanner.Split(SplitBy([]byte{'\n'}))
	for scanner.Scan() {
		line := scanner.Text()
		lineObj := Line{LineIdx: len(msgs.Lines), Raw: line, LineGroupIdx: len(msgs.Blocks)}
		lineObj.Metadata = testForGroupSep(line)
		lineObj.Meaning = ReplyMeaningFromCode(lineObj.Metadata.Code)
		lineObj.Content = lineObj.Raw[lineObj.Metadata.ContentOffset:]
		lineObj.Indent = countIndent(lineObj.Content)
		lineObj.TrimmedLine = strings.TrimSpace(lineObj.Content)
		msgs.Lines = append(msgs.Lines, lineObj)
		if lineObj.Metadata.HasGroupSeperator && lineObj.Metadata.EndOfReply {
			blockObj := Block{
				BlockIndex: len(msgs.Blocks),
				Lines:      msgs.Lines[numLinesRead:],
			}
			msgs.Blocks = append(msgs.Blocks, blockObj)
			numLinesRead = len(msgs.Lines)

			protoInfo := parseBGPProtoInfo(blockObj.Lines)
			if protoInfo != nil {
				return protoInfo
			}
		}
	}
	return nil
}

type BirdClient struct {
	conn      net.Conn
	onConnect func(ctx context.Context) error
}

func NewBirdClientFromSocket(socketPath string) *BirdClient {
	client := new(BirdClient)

	onConnect := func(ctx context.Context) error {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return fmt.Errorf("failed to connect to socket: %v", err)
		}
		client.conn = conn
		return nil
	}
	client.onConnect = onConnect

	return client
}

func (client *BirdClient) Connect(ctx context.Context) error {
	return client.onConnect(ctx)
}

func (client *BirdClient) Close() error {
	return client.conn.Close()
}

func (client *BirdClient) SendCommand(ctx context.Context, command string) error {
	_, err := fmt.Fprintf(client.conn, "%s\n", command)
	return err
}

func (client *BirdClient) GetConnection() net.Conn {
	return client.conn
}

func (client *BirdClient) ShowBGPProtocolInfo(ctx context.Context, protocolName string) (*BGPProtoInfo, error) {
	if protocolName == "" {
		return nil, fmt.Errorf("invalid or empty protocol name, protocol name is required")
	}

	protoInfoChan := make(chan *BGPProtoInfo)
	go func() {
		defer close(protoInfoChan)

		parser := NewBirdBGPProtoInfoParser(client.conn)
		protoInfo := parser.Parse()
		if protoInfo != nil {
			protoInfoChan <- protoInfo
			return
		}
		protoInfoChan <- nil
	}()

	client.SendCommand(ctx, fmt.Sprintf("show protocols all %s", protocolName))

	select {
	case protoInfo := <-protoInfoChan:
		return protoInfo, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
