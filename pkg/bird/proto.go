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
	"time"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
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
	Lines        []Line  `json:"lines"`
	Blocks       []Block `json:"blocks"`
	numLinesRead int     `json:"-"`
}

func (msgs *RawMessages) Init() {
	msgs.Lines = make([]Line, 0)
}

func (msgs *RawMessages) Ingest(line string) *Block {
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
			Lines:      msgs.Lines[msgs.numLinesRead:],
		}
		msgs.Blocks = append(msgs.Blocks, blockObj)
		msgs.numLinesRead = len(msgs.Lines)
		return &blockObj
	}
	return nil
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

// +k8s:deepcopy-gen=true
type ChannelRoutesStat struct {
	Imported  int `json:"imported"`
	Filtered  int `json:"filtered"`
	Exported  int `json:"exported"`
	Preferred int `json:"preferred"`
}

// +k8s:deepcopy-gen=true
type ChannelRouteChangesStatEntry struct {
	Received *int `json:"received,omitempty"`
	Rejected *int `json:"rejected,omitempty"`
	Filtered *int `json:"filtered,omitempty"`
	Ignored  *int `json:"ignored,omitempty"`
	Accepted *int `json:"accepted,omitempty"`
}

// +k8s:deepcopy-gen=true
type ChannelRouteChangesStat struct {
	ImportUpdates   *ChannelRouteChangesStatEntry `json:"import_updates,omitempty"`
	ImportWithdraws *ChannelRouteChangesStatEntry `json:"import_withdraws,omitempty"`
	ExportUpdates   *ChannelRouteChangesStatEntry `json:"export_updates,omitempty"`
	ExportWithdraws *ChannelRouteChangesStatEntry `json:"export_withdraws,omitempty"`
}

// +k8s:deepcopy-gen=true
type BGPCapabilitiesInfo []string

// +k8s:deepcopy-gen=true
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

// +k8s:deepcopy-gen=true
type BGPProtoBasics struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Table string `json:"table"`
	State string `json:"state"`
	Since string `json:"since"`
	Info  string `json:"info"`
}

// +k8s:deepcopy-gen=true
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
	msgs.Init()

	scanner := bufio.NewScanner(parser.reader)
	scanBuf := make([]byte, maxTokenSize)
	scanner.Buffer(scanBuf, maxTokenSize)
	scanner.Split(SplitBy([]byte{'\n'}))
	for scanner.Scan() {
		line := scanner.Text()
		if blockObj := msgs.Ingest(line); blockObj != nil {
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

func (client *BirdClient) SendOneOffCommand(ctx context.Context, command string) (replies []string, err error) {
	resultsChan := make(chan []string)

	go func() {
		defer close(resultsChan)
		msgs := new(RawMessages)
		msgs.Init()
		scanner := bufio.NewScanner(client.conn)
		scanBuf := make([]byte, maxTokenSize)
		scanner.Buffer(scanBuf, maxTokenSize)
		scanner.Split(SplitBy([]byte{'\n'}))
		for scanner.Scan() {
			line := scanner.Text()
			if blockObj := msgs.Ingest(line); blockObj != nil {
				if findLineIdx(blockObj.Lines, `^Reconfig`) >= 0 {
					lines := make([]string, 0)
					for _, lineObj := range msgs.Lines {
						lines = append(lines, lineObj.Content)
					}
					resultsChan <- lines
					return
				}
			}
		}
		resultsChan <- nil
	}()

	_, err = fmt.Fprintf(client.conn, "%s\n", command)
	if err != nil {
		return nil, fmt.Errorf("failed to send command %s to bird: %w", command, err)
	}

	timeoutCtx, cancelTimeout := context.WithTimeout(ctx, 10*time.Second)
	defer cancelTimeout()

	select {
	case replies = <-resultsChan:
		return replies, nil
	case <-timeoutCtx.Done():
		return nil, timeoutCtx.Err()
	}
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

	cmd := fmt.Sprintf("show protocols all %s", protocolName)
	_, err := fmt.Fprintf(client.conn, "%s\n", cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to send command %s to bird: %w", cmd, err)
	}

	select {
	case protoInfo := <-protoInfoChan:
		return protoInfo, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (basics *BGPProtoBasics) IsEqual(other *BGPProtoBasics) bool {
	if basics == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	return basics.Name == other.Name &&
		basics.Proto == other.Proto &&
		basics.Table == other.Table &&
		basics.State == other.State &&
		basics.Since == other.Since &&
		basics.Info == other.Info
}

func (routesStat *ChannelRoutesStat) IsEqual(other *ChannelRoutesStat) bool {
	if routesStat == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	return routesStat.Imported == other.Imported &&
		routesStat.Filtered == other.Filtered &&
		routesStat.Exported == other.Exported &&
		routesStat.Preferred == other.Preferred
}

func (routeChangesStatEntry *ChannelRouteChangesStatEntry) IsEqual(other *ChannelRouteChangesStatEntry) bool {
	if routeChangesStatEntry == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	return pkgutils.CompareIntPointers(routeChangesStatEntry.Received, other.Received) &&
		pkgutils.CompareIntPointers(routeChangesStatEntry.Rejected, other.Rejected) &&
		pkgutils.CompareIntPointers(routeChangesStatEntry.Filtered, other.Filtered) &&
		pkgutils.CompareIntPointers(routeChangesStatEntry.Ignored, other.Ignored) &&
		pkgutils.CompareIntPointers(routeChangesStatEntry.Accepted, other.Accepted)
}

func (routeUpdatesState *ChannelRouteChangesStat) IsEqual(other *ChannelRouteChangesStat) bool {
	if routeUpdatesState == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	return routeUpdatesState.ImportUpdates.IsEqual(other.ImportUpdates) &&
		routeUpdatesState.ImportWithdraws.IsEqual(other.ImportWithdraws) &&
		routeUpdatesState.ExportUpdates.IsEqual(other.ExportUpdates) &&
		routeUpdatesState.ExportWithdraws.IsEqual(other.ExportWithdraws)
}

func (channelInfo *ChannelInfo) IsEqual(other *ChannelInfo) bool {
	if channelInfo == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	if channelInfo.Name != other.Name {
		return false
	}
	if channelInfo.State != other.State {
		return false
	}
	if !pkgutils.CompareIntPointers(channelInfo.Preference, other.Preference) {
		return false
	}
	if channelInfo.InputFilter != other.InputFilter {
		return false
	}
	if channelInfo.OutputFilter != other.OutputFilter {
		return false
	}
	if !pkgutils.CompareStringPointers(channelInfo.BGPNextHop, other.BGPNextHop) {
		return false
	}

	if !channelInfo.RoutesStat.IsEqual(other.RoutesStat) {
		return false
	}

	if !channelInfo.RouteChangesStat.IsEqual(other.RouteChangesStat) {
		return false
	}

	return true
}

func compareChannels(lhs, rhs map[string]ChannelInfo) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	commonSet := make(map[string]*ChannelInfo)
	for k, v_left := range lhs {
		if _, ok := rhs[k]; ok {
			commonSet[k] = &v_left
		}
	}

	if len(commonSet) != len(lhs) || len(commonSet) != len(rhs) {
		return false
	}

	for k, v_right := range rhs {
		v_left, ok := commonSet[k]
		if !ok {
			return false
		}
		if !v_left.IsEqual(&v_right) {
			return false
		}
	}
	return true
}

func (info *BGPProtoInfo) IsEqual(other pkginterfacestub.InterfaceStatus) bool {
	if info == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	rhs, ok := other.(*BGPProtoInfo)
	if !ok {
		return false
	}
	if rhs == nil {
		return false
	}
	if !info.Basics.IsEqual(rhs.Basics) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.VRF, rhs.VRF) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.BGPState, rhs.BGPState) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.NeighborAddress, rhs.NeighborAddress) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.NeighborAS, rhs.NeighborAS) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.LocalAS, rhs.LocalAS) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.NeighborID, rhs.NeighborID) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.Session, rhs.Session) {
		return false
	}
	if !pkgutils.CompareStringPointers(info.SourceAddress, rhs.SourceAddress) {
		return false
	}

	localCaps := make([]string, 0)
	if info.LocalCapabilities != nil {
		for _, cap := range info.LocalCapabilities {
			localCaps = append(localCaps, cap)
		}
	}
	neighborCaps := make([]string, 0)
	if rhs.LocalCapabilities != nil {
		for _, cap := range rhs.LocalCapabilities {
			neighborCaps = append(neighborCaps, cap)
		}
	}
	if !pkgutils.CompareStringSlices(localCaps, neighborCaps) {
		return false
	}

	if !compareChannels(info.Channels, rhs.Channels) {
		return false
	}

	return true
}
