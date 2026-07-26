//! Snapshot-driven terminal UI for live Lens flows.

use std::io::{self, IsTerminal, Stdout};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use lens_core::{FlowState, Sensitivity};
use lens_store::{StoreHandle, StoreSnapshot, StoredFlow};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction as LayoutDirection, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};

const MIN_REFRESH: Duration = Duration::from_millis(50);
const MAX_REFRESH: Duration = Duration::from_secs(2);
const MAX_INSPECTOR_CHARS: usize = 16_384;

/// Runtime settings for the interactive terminal.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TuiConfig {
    /// Capped interval between store snapshots and screen draws.
    pub refresh_rate: Duration,
    /// Whether this run was explicitly started with secret reveal enabled.
    pub reveal: bool,
}

impl TuiConfig {
    /// Creates settings and clamps refreshes to 0.5-20 frames per second.
    #[must_use]
    pub fn new(refresh_rate: Duration, reveal: bool) -> Self {
        Self {
            refresh_rate: refresh_rate.clamp(MIN_REFRESH, MAX_REFRESH),
            reveal,
        }
    }
}

/// State returned after the user leaves the TUI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TuiExit {
    /// Final immutable snapshot, suitable for safe export.
    pub snapshot: StoreSnapshot,
}

/// User-controlled live-flow filters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowFilter {
    /// Exact protocol label, or all protocols when absent.
    pub protocol: Option<String>,
    /// Exact lifecycle state, or all states when absent.
    pub state: Option<FlowState>,
    /// Minimum completed request latency in nanoseconds.
    pub min_latency_nanos: Option<u64>,
    /// Case-insensitive endpoint, error, or message text search.
    pub search: String,
}

impl FlowFilter {
    fn matches(&self, flow: &StoredFlow) -> bool {
        if self
            .protocol
            .as_deref()
            .is_some_and(|protocol| flow.record.protocol.as_deref() != Some(protocol))
        {
            return false;
        }
        if self.state.is_some_and(|state| flow.record.state != state) {
            return false;
        }
        if self.min_latency_nanos.is_some_and(|minimum| {
            flow.messages
                .iter()
                .filter_map(|message| message.latency_nanos)
                .max()
                .unwrap_or_default()
                < minimum
        }) {
            return false;
        }
        if self.search.trim().is_empty() {
            return true;
        }
        let needle = self.search.to_ascii_lowercase();
        let haystack = format!(
            "{} {} {} {} {} {}",
            flow.record.client,
            flow.record.upstream,
            flow.record.protocol.as_deref().unwrap_or("unknown"),
            flow.record.state,
            flow.failure.as_deref().unwrap_or_default(),
            flow.messages
                .iter()
                .map(|message| message.summary.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .to_ascii_lowercase();
        haystack.contains(&needle)
    }

    fn summary(&self) -> String {
        format!(
            "proto={} state={} latency={} search={}",
            self.protocol.as_deref().unwrap_or("all"),
            self.state
                .map_or_else(|| "all".to_string(), |state| state.to_string()),
            self.min_latency_nanos
                .map_or_else(|| "all".to_string(), format_latency),
            if self.search.is_empty() {
                "-"
            } else {
                self.search.as_str()
            }
        )
    }
}

/// Deterministic UI state, separate from terminal I/O for snapshot testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TuiApp {
    snapshot: StoreSnapshot,
    filter: FlowFilter,
    selected: usize,
    inspector_scroll: u16,
    dropped: u64,
    reveal: bool,
    search_mode: bool,
    follow_tail: bool,
}

impl TuiApp {
    /// Creates a view model from the first store snapshot.
    #[must_use]
    pub fn new(snapshot: StoreSnapshot, reveal: bool, dropped: u64) -> Self {
        let mut app = Self {
            snapshot,
            filter: FlowFilter::default(),
            selected: 0,
            inspector_scroll: 0,
            dropped,
            reveal,
            search_mode: false,
            follow_tail: true,
        };
        app.select_tail();
        app
    }

    /// Replaces the immutable snapshot without exposing store mutation to the UI.
    pub fn refresh(&mut self, snapshot: StoreSnapshot, dropped: u64) {
        self.snapshot = snapshot;
        self.dropped = dropped;
        if self.follow_tail {
            self.select_tail();
        } else {
            self.clamp_selection();
        }
    }

    /// Returns the active filter for controls and tests.
    #[must_use]
    pub const fn filter(&self) -> &FlowFilter {
        &self.filter
    }

    /// Applies one keyboard event and returns whether the UI should exit.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            return true;
        }
        if self.search_mode {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.search_mode = false,
                KeyCode::Backspace => {
                    self.filter.search.pop();
                    self.reset_after_filter();
                }
                KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.filter.search.push(character);
                    self.reset_after_filter();
                }
                _ => {}
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous(),
            KeyCode::Home => {
                self.follow_tail = false;
                self.selected = 0;
                self.inspector_scroll = 0;
            }
            KeyCode::End => {
                self.follow_tail = true;
                self.select_tail();
            }
            KeyCode::PageDown => self.inspector_scroll = self.inspector_scroll.saturating_add(8),
            KeyCode::PageUp => self.inspector_scroll = self.inspector_scroll.saturating_sub(8),
            KeyCode::Char('p') => {
                self.filter.protocol = match self.filter.protocol.as_deref() {
                    None => Some("http1".to_string()),
                    Some("http1") => Some("postgres".to_string()),
                    Some("postgres") => Some("tcp".to_string()),
                    _ => None,
                };
                self.reset_after_filter();
            }
            KeyCode::Char('s') => {
                self.filter.state = match self.filter.state {
                    None => Some(FlowState::Open),
                    Some(FlowState::Open) => Some(FlowState::Closed),
                    Some(FlowState::Closed) => Some(FlowState::Failed),
                    Some(FlowState::Failed) => None,
                };
                self.reset_after_filter();
            }
            KeyCode::Char('l') => {
                self.filter.min_latency_nanos = match self.filter.min_latency_nanos {
                    None => Some(1_000_000),
                    Some(1_000_000) => Some(10_000_000),
                    Some(10_000_000) => Some(100_000_000),
                    Some(100_000_000) => Some(1_000_000_000),
                    _ => None,
                };
                self.reset_after_filter();
            }
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.filter.search.clear();
                self.reset_after_filter();
            }
            KeyCode::Char('x') => {
                self.filter = FlowFilter::default();
                self.reset_after_filter();
            }
            _ => {}
        }
        false
    }

    fn visible_indices(&self) -> Vec<usize> {
        self.snapshot
            .flows
            .iter()
            .enumerate()
            .filter_map(|(index, flow)| self.filter.matches(flow).then_some(index))
            .collect()
    }

    fn selected_flow(&self) -> Option<&StoredFlow> {
        self.visible_indices()
            .get(self.selected)
            .and_then(|index| self.snapshot.flows.get(*index))
    }

    fn select_next(&mut self) {
        let length = self.visible_indices().len();
        if length > 0 {
            self.follow_tail = false;
            self.selected = (self.selected + 1).min(length - 1);
            self.inspector_scroll = 0;
        }
    }

    fn select_previous(&mut self) {
        self.follow_tail = false;
        self.selected = self.selected.saturating_sub(1);
        self.inspector_scroll = 0;
    }

    fn select_tail(&mut self) {
        self.selected = self.visible_indices().len().saturating_sub(1);
        self.inspector_scroll = 0;
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.visible_indices().len().saturating_sub(1));
    }

    fn reset_after_filter(&mut self) {
        self.follow_tail = true;
        self.select_tail();
    }
}

/// Returns whether stdout can safely host an interactive terminal.
#[must_use]
pub fn stdout_is_terminal() -> bool {
    io::stdout().is_terminal()
}

/// Runs the interactive terminal until `q` or Ctrl-C.
pub fn run<F>(handle: &StoreHandle, config: TuiConfig, mut dropped: F) -> io::Result<TuiExit>
where
    F: FnMut() -> u64,
{
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error);
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(error) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(error);
        }
    };

    let mut app = TuiApp::new(handle.snapshot(), config.reveal, dropped());
    let result = run_loop(&mut terminal, handle, config, &mut app, &mut dropped);
    let cleanup = restore_terminal(&mut terminal);
    match (result, cleanup) {
        (Ok(exit), Ok(())) => Ok(exit),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn run_loop<F>(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    handle: &StoreHandle,
    config: TuiConfig,
    app: &mut TuiApp,
    dropped: &mut F,
) -> io::Result<TuiExit>
where
    F: FnMut() -> u64,
{
    let mut next_refresh = Instant::now();
    loop {
        let now = Instant::now();
        if now >= next_refresh {
            app.refresh(handle.snapshot(), dropped());
            terminal.draw(|frame| draw(frame, app))?;
            next_refresh = now + config.refresh_rate;
        }
        let wait = next_refresh.saturating_duration_since(Instant::now());
        if !event::poll(wait)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if app.handle_key(key) {
            return Ok(TuiExit {
                snapshot: handle.snapshot(),
            });
        }
        terminal.draw(|frame| draw(frame, app))?;
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    let raw = disable_raw_mode();
    let screen = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor = terminal.show_cursor();
    raw.and(screen).and(cursor)
}

fn draw(frame: &mut Frame<'_>, app: &TuiApp) {
    let regions = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let content = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(regions[1]);

    let redaction = if app.reveal {
        Span::styled(
            "REVEAL MODE",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "SAFE REDACTION",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Lens ", Style::default().add_modifier(Modifier::BOLD)),
        redaction,
        Span::raw(format!(
            "  retained={} evicted={} dropped={}",
            app.snapshot.flows.len(),
            app.snapshot.evicted,
            app.dropped
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Live developer traffic"),
    );
    frame.render_widget(header, regions[0]);

    let visible = app.visible_indices();
    let rows = visible.iter().filter_map(|index| {
        let flow = app.snapshot.flows.get(*index)?;
        Some(Row::new(vec![
            Cell::from(
                flow.record
                    .envelope
                    .flow_id
                    .unwrap_or_default()
                    .get()
                    .to_string(),
            ),
            Cell::from(flow.record.protocol.as_deref().unwrap_or("unknown")),
            Cell::from(flow.record.state.to_string()),
            Cell::from(format!(
                "{} -> {}",
                flow.record.client, flow.record.upstream
            )),
            Cell::from(flow_latency(flow).map_or_else(|| "-".to_string(), format_latency)),
        ]))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(24),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["id", "protocol", "state", "route", "latency"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(format!(
        "Flows {}/{}",
        visible.len(),
        app.snapshot.flows.len()
    )))
    .row_highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");
    let mut state =
        TableState::default().with_selected((!visible.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, content[0], &mut state);

    let inspector = Paragraph::new(inspector_text(app.selected_flow()))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Flow inspector"),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.inspector_scroll, 0));
    frame.render_widget(inspector, content[1]);

    let prompt = if app.search_mode {
        format!("search: {}_  Enter/Esc finish", app.filter.search)
    } else {
        format!(
            "{}  |  j/k select  PgUp/PgDn inspect  p protocol  s status  l latency  / search  x clear  q quit",
            app.filter.summary()
        )
    };
    let footer =
        Paragraph::new(prompt).block(Block::default().borders(Borders::ALL).title("Controls"));
    frame.render_widget(footer, regions[2]);
}

fn inspector_text(flow: Option<&StoredFlow>) -> Text<'static> {
    let Some(flow) = flow else {
        return Text::from("No flow matches the active filters.");
    };
    let mut lines = vec![
        Line::from(format!(
            "route: {} -> {}",
            flow.record.client, flow.record.upstream
        )),
        Line::from(format!(
            "protocol: {}  state: {}  bytes: {} / {}",
            flow.record.protocol.as_deref().unwrap_or("unknown"),
            flow.record.state,
            flow.client_to_upstream_bytes,
            flow.upstream_to_client_bytes
        )),
    ];
    if let Some(failure) = &flow.failure {
        lines.push(Line::from(Span::styled(
            format!("failure: {}", sanitize(failure, 1024)),
            Style::default().fg(Color::Red),
        )));
    }
    if let Some(error) = &flow.decoder_error {
        lines.push(Line::from(Span::styled(
            format!("decoder: {}", sanitize(error, 1024)),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    if flow.messages.is_empty() {
        lines.push(Line::from("No decoded messages."));
    }
    let first_message = flow.messages.len().saturating_sub(200);
    let mut remaining_chars = MAX_INSPECTOR_CHARS;
    if first_message > 0 {
        lines.push(Line::from(format!(
            "... {} older messages omitted from this view ...",
            first_message
        )));
    }
    for message in &flow.messages[first_message..] {
        if remaining_chars == 0 {
            lines.push(Line::from("... inspector character limit reached ..."));
            break;
        }
        let direction = message
            .envelope
            .direction
            .map_or_else(|| "?".to_string(), |direction| direction.to_string());
        let latency = message
            .latency_nanos
            .map_or_else(String::new, |value| format!("  {}", format_latency(value)));
        let flags = format!(
            "{}{}",
            if message.truncated { " truncated" } else { "" },
            if message.envelope.sensitivity == Sensitivity::Redacted {
                " redacted"
            } else {
                ""
            }
        );
        let summary = sanitize(&message.summary, remaining_chars.min(2048));
        remaining_chars = remaining_chars.saturating_sub(summary.chars().count());
        lines.push(Line::from(Span::styled(
            format!("[{direction}] {summary}{latency}{flags}"),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        let body = sanitize(
            &String::from_utf8_lossy(&message.body),
            remaining_chars.min(4096),
        );
        remaining_chars = remaining_chars.saturating_sub(body.chars().count());
        if !body.trim().is_empty() {
            lines.extend(body.lines().map(|line| Line::from(format!("  {line}"))));
        }
        lines.push(Line::from(""));
    }
    Text::from(lines)
}

fn flow_latency(flow: &StoredFlow) -> Option<u64> {
    flow.messages
        .iter()
        .filter_map(|message| message.latency_nanos)
        .max()
}

fn format_latency(nanos: u64) -> String {
    if nanos >= 1_000_000_000 {
        format!("{:.2}s", nanos as f64 / 1_000_000_000.0)
    } else if nanos >= 1_000_000 {
        format!("{:.1}ms", nanos as f64 / 1_000_000.0)
    } else if nanos >= 1_000 {
        format!("{:.1}us", nanos as f64 / 1_000.0)
    } else {
        format!("{nanos}ns")
    }
}

fn sanitize(value: &str, max_chars: usize) -> String {
    let mut safe = String::with_capacity(value.len().min(max_chars));
    for (count, character) in value.chars().enumerate() {
        if count == max_chars {
            safe.push_str("...");
            break;
        }
        match character {
            '\n' | '\t' => safe.push(character),
            '\r' => {}
            value if value.is_control() => safe.push('?'),
            value => safe.push(value),
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use lens_core::{
        Direction, Endpoint, EventEnvelope, EventSource, FlowId, FlowRecord, MessageId,
        MessageRecord, RunId,
    };
    use ratatui::backend::TestBackend;

    use super::*;

    fn flow(id: u64, protocol: &str, state: FlowState, latency: Option<u64>) -> StoredFlow {
        let envelope = EventEnvelope::new("flow.opened", RunId::new(1), EventSource::Proxy)
            .with_flow_id(FlowId::new(id));
        let mut record = FlowRecord::new(
            envelope,
            Endpoint::new("127.0.0.1", 5000 + id as u16),
            Endpoint::new("api.example.test", 443),
        )
        .with_protocol(protocol)
        .with_state(state);
        let message_id = MessageId::new(id);
        record.push_message_id(message_id);
        let message = MessageRecord::new(
            EventEnvelope::new("message.decoded", RunId::new(1), EventSource::Decoder)
                .with_flow_id(FlowId::new(id))
                .with_message_id(message_id)
                .with_direction(Direction::ClientToServer),
            if protocol == "postgres" {
                "Query"
            } else {
                "GET /health"
            },
            b"safe body".to_vec(),
        )
        .with_latency_nanos(latency);
        StoredFlow {
            record,
            client_to_upstream_bytes: 10,
            upstream_to_client_bytes: 20,
            failure: None,
            decoder_error: None,
            messages: vec![message],
        }
    }

    fn snapshot() -> StoreSnapshot {
        StoreSnapshot {
            flows: vec![
                flow(1, "http1", FlowState::Closed, Some(2_000_000)),
                flow(2, "postgres", FlowState::Failed, Some(150_000_000)),
            ],
            evicted: 3,
        }
    }

    #[test]
    fn filters_protocol_status_latency_and_search() {
        let mut app = TuiApp::new(snapshot(), false, 0);
        app.filter.protocol = Some("postgres".to_string());
        app.filter.state = Some(FlowState::Failed);
        app.filter.min_latency_nanos = Some(100_000_000);
        app.filter.search = "query".to_string();
        assert_eq!(app.visible_indices(), vec![1]);
        app.filter.search = "missing".to_string();
        assert!(app.visible_indices().is_empty());
    }

    #[test]
    fn refresh_rate_is_bounded() {
        assert_eq!(
            TuiConfig::new(Duration::from_millis(1), false).refresh_rate,
            MIN_REFRESH
        );
        assert_eq!(
            TuiConfig::new(Duration::from_secs(30), false).refresh_rate,
            MAX_REFRESH
        );
    }

    #[test]
    fn deterministic_terminal_snapshot_shows_safety_and_drop_state() {
        let backend = TestBackend::new(140, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = TuiApp::new(snapshot(), false, 4);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("SAFE REDACTION"));
        assert!(rendered.contains("dropped=4"));
        assert!(rendered.contains("postgres"));
        assert!(rendered.contains("Query"));
    }

    #[test]
    fn reveal_mode_is_visibly_marked() {
        let backend = TestBackend::new(100, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = TuiApp::new(StoreSnapshot::default(), true, 0);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("REVEAL MODE"));
    }
}
