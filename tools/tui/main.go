package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Event mirrors one line from the SSE journal.
type Event struct {
	ActionID  string `json:"action_id"`
	Step      string `json:"step"`
	RiskLevel string `json:"risk_level,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	Command   string `json:"command,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Reason    string `json:"reason,omitempty"`
	MCPServer string `json:"mcp_server,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Engine    any    `json:"engine_event,omitempty"`
}

// EventMsg wraps a decoded event for delivery into the Bubble Tea Update loop.
type EventMsg Event

// ConnStatusMsg reports stream health to the model.
type ConnStatusMsg struct {
	Connected bool
	Err       error
	Stale     bool
	Cursor    int
}

// StreamClient owns the SSE connection lifecycle and persists cursor.
type StreamClient struct {
	BaseURL   string
	seen      map[string]struct{}
	lastRx    time.Time
	cursorPat string
	cursorFile string
}

func NewStreamClient(baseURL string) *StreamClient {
	home, _ := os.UserHomeDir()
	cursorFile := filepath.Join(home, ".rygnal_tui_cursor")
	return &StreamClient{
		BaseURL: baseURL,
		seen:    make(map[string]struct{}),
		cursorFile: cursorFile,
	}
}

func (c *StreamClient) persistCursor(offset int) {
	f, err := os.Create(c.cursorFile)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%d", offset)
}

func (c *StreamClient) readPersistedCursor() int {
	b, err := os.ReadFile(c.cursorFile)
	if err != nil {
		return 0
	}
	off, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return off
}

// Listen runs until ctx is cancelled, reconnecting with exponential backoff
// on any failure, and pushing decoded messages onto out.
func (c *StreamClient) Listen(ctx context.Context, out chan<- tea.Msg) {
	backoff := time.Second
	const maxBackoff = 15 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		offset := c.readPersistedCursor()

		err := c.connectOnce(ctx, out, offset)
		if err != nil {
			out <- ConnStatusMsg{Connected: false, Err: err}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *StreamClient) connectOnce(ctx context.Context, out chan<- tea.Msg, startCursor int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/events/stream", nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	if startCursor > 0 {
		q.Set("cursor", strconv.Itoa(startCursor))
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	out <- ConnStatusMsg{Connected: true}
	c.lastRx = time.Now()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var dataBuf strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(strings.TrimPrefix(line, "data:"))

		case strings.HasPrefix(line, ":"):
			// SSE comment — look for cursor in heartbeat: ": heartbeat cursor=12345"
			if strings.Contains(line, "cursor=") {
				parts := strings.Split(line, "cursor=")
				if len(parts) > 1 {
					v := strings.TrimSpace(parts[1])
					v = strings.Trim(v, "\n\r")
					if off, err := strconv.Atoi(v); err == nil {
						c.persistCursor(off)
						// notify model of updated cursor
						out <- ConnStatusMsg{Connected: true, Cursor: off}
					}
				}
			}

		case line == "":
			if dataBuf.Len() == 0 {
				continue
			}
			raw := strings.TrimSpace(dataBuf.String())
			dataBuf.Reset()
			c.lastRx = time.Now()

			var ev Event
			if err := json.Unmarshal([]byte(raw), &ev); err != nil {
				continue
			}

			key := ev.ActionID + "|" + ev.Step
			if _, dup := c.seen[key]; dup {
				continue
			}
			c.seen[key] = struct{}{}

			out <- EventMsg(ev)
		}
	}
	return scanner.Err()
}

// ---------------- Bubble Tea model ----------------

type model struct {
	steps map[string]bool
	// structured events (keeps full JSON payloads)
	events []Event
	// index of currently selected event in events
	selected int
	// whether details pane is visible
	showDetails bool
	// follow mode (auto-scroll to newest)
	follow bool
	// quick filter (prefix match against ActionID)
	filter string
	// input mode for entering filter
	inputMode bool
	inputBuffer string
	// show help overlay
	showHelp bool
	// show raw JSON instead of typed struct
	rawJSON bool
	// map of action_id to timeline of events
	timeline map[string][]Event
	// persisted history path
	historyFile string
	// last seen SSE cursor offset
	lastCursor int

	msgs []string
	status string
	spinnerIndex int
	spinnerChars string
	active bool
	totalEvents int
	lastEvent time.Time
}

func initialModel() model {
	home, _ := os.UserHomeDir()
	hist := filepath.Join(home, ".rygnal_tui_history.jsonl")
	return model{
		steps: map[string]bool{
			"understood.action": false,
			"risk.assessed":     false,
			"policy.checked":    false,
			"decision.made":     false,
		},
		events:      []Event{},
		selected:    0,
		showDetails: true,
		timeline:    map[string][]Event{},
		historyFile: hist,
		msgs:        []string{},
		status:      "connecting",
		spinnerIndex: 0,
		spinnerChars: `|/-\\`,
		active:      false,
	}
}

func (m model) Init() tea.Cmd {
	// start spinner ticking
	return tickCmd()
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch v := msg.(type) {
	case tickMsg:
		if m.active {
			m.spinnerIndex = (m.spinnerIndex + 1) % len(m.spinnerChars)
		}
		cmd = tickCmd()

	case EventMsg:
		e := Event(v)
		m.steps[e.Step] = true
		// append structured event and update timeline
		m.events = append(m.events, e)
		if _, ok := m.timeline[e.ActionID]; !ok {
			m.timeline[e.ActionID] = []Event{}
		}
		m.timeline[e.ActionID] = append(m.timeline[e.ActionID], e)
		// keep selected at the latest
		if m.follow {
			m.selected = len(m.events) - 1
		}
		// persist history line
		_ = appendEventToHistory(m.historyFile, e)
		// color risk label
		risk := strings.ToLower(e.RiskLevel)
		badge := ""
		switch risk {
		case "high":
			badge = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("HIGH")
		case "medium":
			badge = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("MED")
		case "low":
			badge = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("LOW")
		default:
			badge = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("NA")
		}
		line := fmt.Sprintf("%s %s %s %s", e.Timestamp, badge, e.Step, e.ActionID)
		if e.Command != "" {
			line = fmt.Sprintf("%s — %s", line, e.Command)
		}
		m.msgs = append(m.msgs, line)
		if len(m.msgs) > 200 { m.msgs = m.msgs[len(m.msgs)-200:] }
		m.status = "connected"
		m.active = true
		m.totalEvents++
		// parse timestamp if present
		if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil {
			m.lastEvent = t
		} else {
			m.lastEvent = time.Now()
		}
	case ConnStatusMsg:
		if v.Connected {
			m.status = "connected"
			if v.Cursor > 0 {
				m.lastCursor = v.Cursor
			}
		} else {
			m.status = "disconnected"
			if v.Err != nil {
				m.msgs = append(m.msgs, "error: "+v.Err.Error())
			}
		}
	case tea.KeyMsg:
		// handle input mode first
		if m.inputMode {
			switch v.Type {
			case tea.KeyEnter:
				m.filter = strings.TrimSpace(m.inputBuffer)
				m.inputBuffer = ""
				m.inputMode = false
			case tea.KeyBackspace:
				if len(m.inputBuffer) > 0 {
					m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
				}
			default:
				// append printable runes
				if r := v.Runes; len(r) > 0 {
					m.inputBuffer += string(r)
				}
			}
			return m, nil
		}

		if v.String() == "ctrl+c" {
			return m, tea.Quit
		}
		switch v.String() {
		case "up", "k":
			if len(m.events) > 0 && m.selected > 0 {
				m.selected--
				m.follow = false
			}
		case "down", "j":
			if len(m.events) > 0 && m.selected < len(m.events)-1 {
				m.selected++
				m.follow = false
			}
		case "enter", " ":
			m.showDetails = !m.showDetails
		case "f":
			m.follow = !m.follow
			if m.follow {
				m.selected = len(m.events) - 1
			}
		case "/":
			m.inputMode = true
			m.inputBuffer = ""
		case "r":
			m.rawJSON = !m.rawJSON
		case "e":
			if len(m.events) > 0 {
				if path, err := exportSelectedEvent(m.events[m.selected]); err == nil {
					m.msgs = append(m.msgs, "exported to "+path)
				} else {
					m.msgs = append(m.msgs, "export failed: "+err.Error())
				}
			}
		case "s":
			// manual save
			_ = saveAllHistory(m.historyFile, m.events)
			m.msgs = append(m.msgs, "history saved")
		case "?":
			m.showHelp = !m.showHelp
		case "c":
			// clear filter
			m.filter = ""
		}
	}
	return m, cmd
}

// appendEventToHistory writes a single event as JSONL to historyFile (creates file if needed)
func appendEventToHistory(historyFile string, e Event) error {
	f, err := os.OpenFile(historyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// saveAllHistory overwrites history file with current events
func saveAllHistory(historyFile string, events []Event) error {
	tmp := historyFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	f.Close()
	return os.Rename(tmp, historyFile)
}

// loadHistory reads JSONL history and returns events (truncates to last 1000)
func loadHistory(historyFile string) ([]Event, error) {
	b, err := os.ReadFile(historyFile)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	evs := make([]Event, 0, len(lines))
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			continue
		}
		evs = append(evs, e)
	}
	// keep reasonable size
	if len(evs) > 1000 {
		evs = evs[len(evs)-1000:]
	}
	return evs, nil
}

func (m model) View() string {
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")).Render("Rygnal Workflow Monitor")
	statusColor := lipgloss.Color("10")
	if m.status != "connected" {
		statusColor = lipgloss.Color("9")
	}
	status := lipgloss.NewStyle().Foreground(statusColor).Render(strings.ToUpper(m.status))
	flags := []string{}
	if m.follow {
		flags = append(flags, "follow")
	}
	if m.filter != "" {
		flags = append(flags, "filter="+m.filter)
	}
	if m.rawJSON {
		flags = append(flags, "raw")
	}
	flagText := ""
	if len(flags) > 0 {
		flagText = "  [" + strings.Join(flags, ",") + "]"
	}
	headerLine := fmt.Sprintf("%s  •  %s%s", header, status, flagText)

	metrics := fmt.Sprintf("events: %d", m.totalEvents)
	if !m.lastEvent.IsZero() {
		metrics = fmt.Sprintf("%s  |  last: %s", metrics, m.lastEvent.Format("15:04:05"))
	}
	if m.lastCursor > 0 {
		metrics = fmt.Sprintf("%s  |  cursor: %d", metrics, m.lastCursor)
	}
	spinnerView := ""
	if m.active && len(m.spinnerChars) > 0 {
		spinnerView = string(m.spinnerChars[m.spinnerIndex])
	}
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(fmt.Sprintf("%s  %s  (Ctrl+C quit, Enter details, / filter, f follow, r raw, e export, ? help)", metrics, spinnerView))

	workflowPanel := m.renderWorkflowPanel()
	activityPanel := m.renderActivityPanel()
	detailPanel := m.renderDetailPanel()

	body := lipgloss.JoinHorizontal(lipgloss.Top, workflowPanel, detailPanel)
	body = lipgloss.JoinVertical(lipgloss.Left, body, activityPanel)

	if m.showHelp {
		help := "Keys: ↑/↓ or j/k select, Enter toggle detail pane, f follow, / filter, c clear, r raw JSON, e export, s save history, ? help"
		return fmt.Sprintf("%s\n\n%s\n\n%s", headerLine, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(help), footer)
	}
	if m.inputMode {
		prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render(fmt.Sprintf("filter: %s", m.inputBuffer))
		return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", headerLine, body, prompt, footer)
	}
	return fmt.Sprintf("%s\n\n%s\n\n%s", headerLine, body, footer)
}

func (m model) renderWorkflowPanel() string {
	stages := []struct {
		name string
		step string
	}{
		{name: "Understood", step: "understood.action"},
		{name: "Risk", step: "risk.assessed"},
		{name: "Policy", step: "policy.checked"},
		{name: "Decision", step: "decision.made"},
	}
	rows := make([]string, 0, len(stages))
	for _, stage := range stages {
		marker := "○"
		color := lipgloss.Color("8")
		if m.steps[stage.step] {
			marker = "●"
			color = lipgloss.Color("10")
		}
		rows = append(rows, lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%s %s", marker, stage.name)))
	}
	content := strings.Join(rows, "\n")
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(30).Render("Workflow stages\n\n" + content)
	return box
}

func (m model) renderActivityPanel() string {
	items := make([]string, 0, len(m.events))
	for i := len(m.events) - 1; i >= 0; i-- {
		e := m.events[i]
		if m.filter != "" && !strings.HasPrefix(e.ActionID, m.filter) {
			continue
		}
		badge := riskBadge(e.RiskLevel)
		prefix := "  "
		if i == m.selected {
			prefix = "▶ "
		}
		line := fmt.Sprintf("%s %s %s", prefix, badge, e.Step)
		if e.ActionID != "" {
			line += " · " + e.ActionID
		}
		if e.Command != "" {
			line += " · " + e.Command
		}
		items = append(items, line)
		if len(items) >= 12 {
			break
		}
	}
	if len(items) == 0 {
		items = []string{"No matching activity"}
	}
	content := strings.Join(items, "\n")
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(90).Render("Recent activity\n\n" + content)
}

func (m model) renderDetailPanel() string {
	boxWidth := 46
	if len(m.events) == 0 {
		return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(boxWidth).Render("Selected action\n\nWaiting for workflow events...")
	}
	idx := m.selected
	if idx < 0 || idx >= len(m.events) {
		idx = len(m.events) - 1
	}
	sel := m.events[idx]
	var pretty []byte
	if m.rawJSON {
		pretty, _ = json.Marshal(sel)
	} else {
		pretty, _ = json.MarshalIndent(sel, "", "  ")
	}
	tl := m.timeline[sel.ActionID]
	sort.SliceStable(tl, func(i, j int) bool {
		return tl[i].Timestamp < tl[j].Timestamp
	})
	tlBuilder := &strings.Builder{}
	for _, te := range tl {
		tlBuilder.WriteString(fmt.Sprintf("• %s %s %s\n", te.Timestamp, te.Step, te.Verdict))
	}
	body := fmt.Sprintf("Action: %s\nStage: %s\nRisk: %s\nVerdict: %s\nReason: %s\n\nTimeline:\n%s", sel.ActionID, sel.Step, sel.RiskLevel, sel.Verdict, sel.Reason, tlBuilder.String())
	if m.showDetails {
		body = fmt.Sprintf("%s\n\nPayload:\n%s", body, string(pretty))
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(boxWidth).Render("Selected action\n\n" + body)
}

func riskBadge(level string) string {
	risk := strings.ToLower(level)
	switch risk {
	case "high":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("HIGH")
	case "medium":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("MED")
	case "low":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("LOW")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("NA")
	}
}

// exportSelectedEvent writes the selected event to a temp file and returns its path
func exportSelectedEvent(e Event) (string, error) {
	f, err := os.CreateTemp("", "rygnal_event_*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func main() {
	base := flag.String("base", "http://127.0.0.1:8787", "Rygnal base URL")
	flag.Parse()

	m := initialModel()
	// attempt to load persisted history
	if evs, err := loadHistory(m.historyFile); err == nil {
		m.events = evs
		// rebuild timeline
		for _, e := range evs {
			if _, ok := m.timeline[e.ActionID]; !ok {
				m.timeline[e.ActionID] = []Event{}
			}
			m.timeline[e.ActionID] = append(m.timeline[e.ActionID], e)
		}
		m.totalEvents = len(evs)
		if len(evs) > 0 {
			last := evs[len(evs)-1]
			if t, err := time.Parse(time.RFC3339, last.Timestamp); err == nil {
				m.lastEvent = t
			}
		}
	}

	p := tea.NewProgram(m)
	out := make(chan tea.Msg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := NewStreamClient(*base)
	go client.Listen(ctx, out)

	// deliver messages from out to the Bubble Tea program
	go func() {
		for m := range out {
			p.Send(m)
		}
	}()

	// handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
		p.Send(tea.Quit())
	}()

	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
