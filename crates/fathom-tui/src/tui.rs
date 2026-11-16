//! The ratatui frontend: three screens over the workflow
//! engine.
//!
//! The App is pure state plus transitions — key and workflow
//! events in, draws out — so every screen is testable on
//! ratatui's `TestBackend` without a terminal. `main` owns the
//! terminal, the engine thread, and the channels.

use crate::config::{
    KNOWN_MCPS, Language, Provider, RunConfig, RunMode, SourceLanguageMode, TARGET_LANGUAGE,
    TranslateConfig,
};
use crate::engine::format_event;
use crate::error::WorkflowError;
use crate::events::{ApprovalDecision, RunOutcome, WorkflowEvent};
use crate::stages::{Stage, StageStatus};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

/// Most lines kept in the run view's log pane.
pub const LOG_LINES_MAX: usize = 1_000;
/// Most entries counted by the picker's facts walk; past the
/// cap the counts are floors and the UI says so.
pub const FACTS_FILES_MAX: u64 = 5_000;

/// Which screen the operator is looking at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    /// Run configuration.
    Configure,
    /// Directory picking.
    PickDir,
    /// A run in progress (or finished).
    Run,
}

/// Facts about a directory, for the picker's facts line.
#[derive(Clone, Debug, Default)]
pub struct DirFacts {
    /// Total bytes, when counted.
    pub bytes: Option<u64>,
    /// True when the walk hit its cap (counts are floors).
    pub capped: bool,
    /// Whether the directory exists.
    pub exists: bool,
    /// Files counted, when counted.
    pub files: Option<u64>,
    /// Whether the directory can be read.
    pub readable: bool,
}

/// Count files and bytes under `dir`, bounded; never follows
/// symlinks, never fails — unreadable subtrees are skipped.
pub fn compute_facts(dir: &std::path::Path) -> DirFacts {
    let mut facts = DirFacts::default();
    let Ok(metadata) = std::fs::metadata(dir) else {
        return facts;
    };
    if !metadata.is_dir() {
        return facts;
    }
    facts.exists = true;
    if std::fs::read_dir(dir).is_err() {
        return facts;
    }
    facts.readable = true;
    let mut files: u64 = 0;
    let mut bytes: u64 = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files += 1;
                bytes += entry.metadata().map(|meta| meta.len()).unwrap_or(0);
                if files >= FACTS_FILES_MAX {
                    facts.capped = true;
                    facts.files = Some(files);
                    facts.bytes = Some(bytes);
                    return facts;
                }
            }
        }
    }
    facts.files = Some(files);
    facts.bytes = Some(bytes);
    facts
}

/// Directory-picker state.
pub struct Picker {
    /// The directory being browsed.
    pub current: PathBuf,
    /// Subdirectories of `current` (plus the parent, first).
    pub entries: Vec<PathBuf>,
    /// A problem to show the operator, if any.
    pub error: Option<String>,
    /// Facts about the confirm candidate.
    pub facts: DirFacts,
    /// The path text being edited.
    pub input: String,
    /// True when keystrokes edit `input`; false for the list.
    pub input_active: bool,
    /// Selected row in `entries`.
    pub selected: usize,
}

impl Picker {
    fn new(start: PathBuf) -> Picker {
        let current = start
            .canonicalize()
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
        let mut picker = Picker {
            current: current.clone(),
            entries: Vec::new(),
            error: None,
            facts: DirFacts::default(),
            input: current.display().to_string(),
            input_active: true,
            selected: 0,
        };
        picker.refresh();
        picker
    }

    /// The directory Enter would confirm: the typed path when
    /// the input has been edited, else the browsed directory.
    pub fn candidate(&self) -> PathBuf {
        let typed = PathBuf::from(self.input.trim());
        if typed == self.current || self.input.trim().is_empty() {
            self.current.clone()
        } else {
            typed
        }
    }

    fn refresh(&mut self) {
        let mut entries = Vec::new();
        if let Some(parent) = self.current.parent() {
            entries.push(parent.to_path_buf());
        }
        if let Ok(read) = std::fs::read_dir(&self.current) {
            let mut dirs: Vec<PathBuf> = read
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            dirs.sort();
            entries.extend(dirs);
        }
        self.entries = entries;
        if self.selected >= self.entries.len() {
            self.selected = 0;
        }
        self.facts = compute_facts(&self.candidate());
    }
}

/// Which control group has focus on the configuration screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormFocus {
    /// Source-language mode.
    Language,
    /// MCP multi-select.
    Mcps,
    /// Plan / auto.
    Mode,
    /// Cloud / local / both.
    Provider,
    /// The start button.
    Start,
    /// Translation on/off.
    Translate,
}

impl FormFocus {
    /// Focus order for Tab.
    pub const ORDER: [FormFocus; 6] = [
        FormFocus::Provider,
        FormFocus::Mode,
        FormFocus::Mcps,
        FormFocus::Translate,
        FormFocus::Language,
        FormFocus::Start,
    ];

    fn next(self) -> FormFocus {
        let index = FormFocus::ORDER
            .iter()
            .position(|f| *f == self)
            .unwrap_or(0);
        FormFocus::ORDER[(index + 1) % FormFocus::ORDER.len()]
    }
}

/// Run-configuration form state.
pub struct ConfigForm {
    /// A validation problem to show, if any.
    pub error: Option<String>,
    /// Focused control group.
    pub focus: FormFocus,
    /// Language selector row: 0 = auto, 1.. = `Language::ALL`.
    pub lang_index: usize,
    /// Checked state per `KNOWN_MCPS` row.
    pub mcp_checked: Vec<bool>,
    /// Cursor row in the MCP list.
    pub mcp_cursor: usize,
    /// Plan or auto.
    pub mode: RunMode,
    /// Provider choice.
    pub provider: Provider,
    /// The chosen target directory.
    pub target: PathBuf,
    /// Translation toggle.
    pub translate_on: bool,
}

impl ConfigForm {
    fn new(target: PathBuf) -> ConfigForm {
        let mcp_checked = KNOWN_MCPS
            .iter()
            .map(|name| crate::config::DEFAULT_MCPS.contains(name))
            .collect();
        ConfigForm {
            error: None,
            focus: FormFocus::Provider,
            lang_index: 0,
            mcp_checked,
            mcp_cursor: 0,
            mode: RunMode::Plan,
            provider: Provider::Local,
            target,
            translate_on: true,
        }
    }

    /// The selected source-language mode.
    pub fn source_mode(&self) -> SourceLanguageMode {
        if self.lang_index == 0 {
            SourceLanguageMode::Auto
        } else {
            SourceLanguageMode::Fixed(Language::ALL[self.lang_index - 1])
        }
    }

    /// Build and validate the run configuration.
    pub fn to_config(&self) -> Result<RunConfig, WorkflowError> {
        let mcps = KNOWN_MCPS
            .iter()
            .zip(self.mcp_checked.iter())
            .filter(|(_, checked)| **checked)
            .map(|(name, _)| name.to_string())
            .collect();
        let config = RunConfig {
            mcps,
            mode: self.mode,
            output_root: PathBuf::from("fathom-runs"),
            provider: self.provider,
            target_dir: self.target.clone(),
            translate: TranslateConfig {
                enabled: self.translate_on,
                mode: self.source_mode(),
            },
        };
        config.validate()?;
        Ok(config)
    }
}

/// Run-view state, fed by the engine's event stream.
pub struct RunView {
    /// True while the engine waits at the plan boundary.
    pub approval_pending: bool,
    /// Hundreds of milliseconds since the run started.
    pub elapsed_ticks: u64,
    /// Log lines (bounded; oldest dropped).
    pub log: Vec<String>,
    /// The note being typed, when editing.
    pub note: Option<String>,
    /// The terminal outcome, when finished.
    pub outcome: Option<RunOutcome>,
    /// Where artifacts are landing.
    pub run_dir: Option<PathBuf>,
    /// (stage, status, summary) in pipeline order.
    pub stages: Vec<(Stage, StageStatus, String)>,
}

impl RunView {
    fn new() -> RunView {
        RunView {
            approval_pending: false,
            elapsed_ticks: 0,
            log: Vec::new(),
            note: None,
            outcome: None,
            run_dir: None,
            stages: Stage::SEQUENCE
                .iter()
                .map(|stage| (*stage, StageStatus::Pending, String::new()))
                .collect(),
        }
    }

    fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > LOG_LINES_MAX {
            let excess = self.log.len() - LOG_LINES_MAX;
            self.log.drain(0..excess);
        }
    }
}

/// The whole frontend state.
pub struct App {
    /// Configuration form (valid once a target was picked).
    pub form: Option<ConfigForm>,
    /// Directory picker.
    pub picker: Picker,
    /// Set when the operator asked to quit.
    pub quit: bool,
    /// Run view (valid once a run started).
    pub run: Option<RunView>,
    /// Current screen.
    pub screen: Screen,
    /// A confirmed configuration waiting for `main` to spawn
    /// the engine thread with it.
    start_request: Option<RunConfig>,
}

impl App {
    /// A new app on the picker screen, browsing `start`.
    pub fn new(start: PathBuf) -> App {
        App {
            form: None,
            picker: Picker::new(start),
            quit: false,
            run: None,
            screen: Screen::PickDir,
            start_request: None,
        }
    }

    /// Take a pending run start, if the operator confirmed
    /// one. `main` calls this each loop turn.
    pub fn take_start_request(&mut self) -> Option<RunConfig> {
        self.start_request.take()
    }

    /// Advance the elapsed clock (called on a fixed cadence).
    pub fn tick(&mut self) {
        if let Some(run) = &mut self.run
            && run.outcome.is_none()
        {
            run.elapsed_ticks += 1;
        }
    }

    /// Fold one engine event into the run view.
    pub fn on_workflow_event(&mut self, event: WorkflowEvent) {
        let Some(run) = &mut self.run else {
            return;
        };
        match &event {
            WorkflowEvent::ApprovalRequested { .. } => {
                run.approval_pending = true;
            }
            WorkflowEvent::RunFinished { outcome } => {
                run.outcome = Some(outcome.clone());
                run.approval_pending = false;
                run.note = None;
            }
            WorkflowEvent::RunStarted { run_dir, .. } => {
                run.run_dir = Some(run_dir.clone());
            }
            WorkflowEvent::StageFinished {
                stage,
                status,
                summary,
            } => {
                if let Some(row) = run.stages.iter_mut().find(|(s, _, _)| s == stage) {
                    row.1 = *status;
                    row.2 = summary.clone();
                }
            }
            WorkflowEvent::StageStarted { stage } => {
                if let Some(row) = run.stages.iter_mut().find(|(s, _, _)| s == stage) {
                    row.1 = StageStatus::Running;
                }
            }
            _ => {}
        }
        let line = format_event(&event);
        run.push_log(line);
    }

    /// Handle one key press. `approvals`/`abort` wire the run
    /// screen to the engine; they are unused on other screens.
    pub fn on_key(
        &mut self,
        key: KeyEvent,
        approvals: Option<&Sender<ApprovalDecision>>,
        abort: &AtomicBool,
    ) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            match self.screen {
                Screen::Run => abort.store(true, Ordering::SeqCst),
                _ => self.quit = true,
            }
            return;
        }
        match self.screen {
            Screen::PickDir => self.on_picker_key(key),
            Screen::Configure => self.on_form_key(key),
            Screen::Run => self.on_run_key(key, approvals, abort),
        }
    }

    fn on_picker_key(&mut self, key: KeyEvent) {
        let picker = &mut self.picker;
        if picker.input_active {
            match key.code {
                KeyCode::Backspace => {
                    picker.input.pop();
                    picker.facts = compute_facts(&picker.candidate());
                }
                KeyCode::Char(ch) => {
                    picker.input.push(ch);
                    picker.facts = compute_facts(&picker.candidate());
                }
                KeyCode::Enter => self.confirm_target(),
                KeyCode::Esc => self.quit = true,
                KeyCode::Tab => picker.input_active = false,
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('c') => self.confirm_target(),
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Down => {
                if picker.selected + 1 < picker.entries.len() {
                    picker.selected += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(dir) = picker.entries.get(picker.selected).cloned() {
                    picker.current = dir;
                    picker.input = picker.current.display().to_string();
                    picker.selected = 0;
                    picker.refresh();
                }
            }
            KeyCode::Tab => picker.input_active = true,
            KeyCode::Up => {
                picker.selected = picker.selected.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn confirm_target(&mut self) {
        let candidate = self.picker.candidate();
        let probe = RunConfig::new(candidate.clone());
        match probe.validate() {
            Ok(()) => {
                self.picker.error = None;
                self.form = Some(ConfigForm::new(candidate));
                self.screen = Screen::Configure;
            }
            Err(error) => {
                self.picker.error = Some(error.to_string());
            }
        }
    }

    fn on_form_key(&mut self, key: KeyEvent) {
        let Some(form) = &mut self.form else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.screen = Screen::PickDir,
            KeyCode::Tab => form.focus = form.focus.next(),
            KeyCode::BackTab => {
                let order = FormFocus::ORDER;
                let index = order.iter().position(|f| *f == form.focus).unwrap_or(0);
                form.focus = order[(index + order.len() - 1) % order.len()];
            }
            KeyCode::Up | KeyCode::Left => self.form_adjust(-1),
            KeyCode::Down | KeyCode::Right => self.form_adjust(1),
            KeyCode::Char(' ') => self.form_toggle(),
            KeyCode::Enter if form.focus == FormFocus::Start => self.try_start(),
            KeyCode::Enter => {}
            _ => {}
        }
    }

    fn form_adjust(&mut self, delta: i32) {
        let Some(form) = &mut self.form else {
            return;
        };
        match form.focus {
            FormFocus::Language => {
                let count = Language::ALL.len() as i32 + 1;
                let next = (form.lang_index as i32 + delta).rem_euclid(count);
                form.lang_index = next as usize;
            }
            FormFocus::Mcps => {
                let count = KNOWN_MCPS.len() as i32;
                let next = (form.mcp_cursor as i32 + delta).rem_euclid(count);
                form.mcp_cursor = next as usize;
            }
            FormFocus::Mode => {
                form.mode = match (form.mode, delta) {
                    (RunMode::Plan, _) => RunMode::Auto,
                    (RunMode::Auto, _) => RunMode::Plan,
                };
            }
            FormFocus::Provider => {
                let all = Provider::ALL;
                let index = all.iter().position(|p| *p == form.provider).unwrap_or(0);
                let next = (index as i32 + delta).rem_euclid(all.len() as i32);
                form.provider = all[next as usize];
            }
            FormFocus::Start | FormFocus::Translate => {}
        }
    }

    fn form_toggle(&mut self) {
        let Some(form) = &mut self.form else {
            return;
        };
        match form.focus {
            FormFocus::Mcps => {
                let name = KNOWN_MCPS[form.mcp_cursor];
                if crate::config::REQUIRED_MCPS.contains(&name) {
                    form.error = Some(format!("{name} is required and stays on"));
                } else {
                    let row = form.mcp_cursor;
                    form.mcp_checked[row] = !form.mcp_checked[row];
                    form.error = None;
                }
            }
            FormFocus::Translate => {
                form.translate_on = !form.translate_on;
            }
            _ => {}
        }
    }

    fn try_start(&mut self) {
        let Some(form) = &self.form else {
            return;
        };
        match form.to_config() {
            Ok(config) => {
                self.run = Some(RunView::new());
                self.start_request = Some(config);
                self.screen = Screen::Run;
            }
            Err(error) => {
                if let Some(form) = &mut self.form {
                    form.error = Some(error.to_string());
                }
            }
        }
    }

    fn on_run_key(
        &mut self,
        key: KeyEvent,
        approvals: Option<&Sender<ApprovalDecision>>,
        abort: &AtomicBool,
    ) {
        let Some(run) = &mut self.run else {
            return;
        };
        if let Some(note) = &mut run.note {
            match key.code {
                KeyCode::Backspace => {
                    note.pop();
                }
                KeyCode::Char(ch) => note.push(ch),
                KeyCode::Enter => {
                    let text = run.note.take().unwrap_or_default();
                    run.approval_pending = false;
                    if let Some(sender) = approvals {
                        let _ = sender.send(ApprovalDecision::ApproveWithNote(text));
                    }
                }
                KeyCode::Esc => run.note = None,
                _ => {}
            }
            return;
        }
        if run.approval_pending {
            match key.code {
                KeyCode::Char('a') => {
                    run.approval_pending = false;
                    if let Some(sender) = approvals {
                        let _ = sender.send(ApprovalDecision::Approve);
                    }
                }
                KeyCode::Char('e') => run.note = Some(String::new()),
                KeyCode::Char('x') => {
                    run.approval_pending = false;
                    if let Some(sender) = approvals {
                        let _ = sender.send(ApprovalDecision::Abort);
                    }
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') if run.outcome.is_some() => self.quit = true,
            KeyCode::Char('r') if run.outcome.is_some() => {
                self.run = None;
                self.form = None;
                self.screen = Screen::PickDir;
            }
            KeyCode::Char('x') => abort.store(true, Ordering::SeqCst),
            _ => {}
        }
    }
}

impl App {
    /// Render the current screen.
    pub fn draw(&self, frame: &mut Frame) {
        match self.screen {
            Screen::Configure => self.draw_configure(frame),
            Screen::PickDir => self.draw_picker(frame),
            Screen::Run => self.draw_run(frame),
        }
    }

    fn draw_picker(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(frame.area());
        let title = Paragraph::new("fathom — clean-room rebuild workflow")
            .style(Style::default().add_modifier(Modifier::BOLD))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Target directory"),
            );
        frame.render_widget(title, chunks[0]);
        let picker = &self.picker;
        let items: Vec<ListItem> = picker
            .entries
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let label = if index == 0 && picker.current.parent() == Some(path.as_path()) {
                    format!("../  ({})", path.display())
                } else {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.display().to_string())
                };
                ListItem::new(label)
            })
            .collect();
        let mut state = ratatui::widgets::ListState::default();
        if !picker.input_active {
            state.select(Some(picker.selected));
        }
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Browse: {}  (path: {})",
                picker.current.display(),
                picker.input
            )))
            .highlight_style(Style::default().fg(Color::Yellow));
        frame.render_stateful_widget(list, chunks[1], &mut state);
        let facts = &picker.facts;
        let facts_text = if !facts.exists {
            "path does not exist".to_string()
        } else if !facts.readable {
            "directory is not readable".to_string()
        } else {
            let count = facts.files.unwrap_or(0);
            let floor = if facts.capped { " (floor, capped)" } else { "" };
            format!(
                "{} files, {}{}",
                count,
                crate::documents::human_bytes(facts.bytes.unwrap_or(0)),
                floor
            )
        };
        let status = match &picker.error {
            Some(error) => format!("error: {error}"),
            None => facts_text,
        };
        frame.render_widget(
            Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("Facts")),
            chunks[2],
        );
        frame.render_widget(
            Paragraph::new("type path · Tab: browse · Enter: descend/confirm · c: use this directory · q: quit"),
            chunks[3],
        );
    }

    fn draw_configure(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(3),
                Constraint::Length(9),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(frame.area());
        let Some(form) = &self.form else {
            return;
        };
        let focus_mark = |focus: FormFocus| if form.focus == focus { "▶" } else { " " };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(format!("Target: {}", form.target.display())),
                Line::from(format!("Build language: {TARGET_LANGUAGE} (fixed)")),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Run configuration"),
            ),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{} Provider: {}    {} Mode: {}",
                focus_mark(FormFocus::Provider),
                form.provider.label(),
                focus_mark(FormFocus::Mode),
                form.mode.label()
            ))
            .block(Block::default().borders(Borders::ALL).title("Route")),
            chunks[1],
        );
        let items: Vec<ListItem> = KNOWN_MCPS
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let checked = if form.mcp_checked[index] {
                    "[x]"
                } else {
                    "[ ]"
                };
                let locked = if crate::config::REQUIRED_MCPS.contains(name) {
                    " (required)"
                } else {
                    ""
                };
                let cursor = if form.focus == FormFocus::Mcps && form.mcp_cursor == index {
                    "▶"
                } else {
                    " "
                };
                ListItem::new(format!("{cursor} {checked} {name}{locked}"))
            })
            .collect();
        frame.render_widget(
            List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("MCPs (space toggles; the run's allowed tool set)"),
            ),
            chunks[2],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{} Translation: {}    {} Source language: {}",
                focus_mark(FormFocus::Translate),
                if form.translate_on { "on" } else { "off" },
                focus_mark(FormFocus::Language),
                form.source_mode().label()
            ))
            .block(Block::default().borders(Borders::ALL).title("Translation")),
            chunks[3],
        );
        let start_style = if form.focus == FormFocus::Start {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        frame.render_widget(
            Paragraph::new(Span::styled("▶ Start run", start_style))
                .block(Block::default().borders(Borders::ALL).title("Start")),
            chunks[4],
        );
        let status = form.error.clone().unwrap_or_default();
        frame.render_widget(Paragraph::new(status), chunks[5]);
        frame.render_widget(
            Paragraph::new(
                "Tab: next group · ↑↓←→: adjust · space: toggle · Enter on Start: run · Esc: back",
            ),
            chunks[6],
        );
    }

    fn draw_run(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(3)])
            .split(frame.area());
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(chunks[0]);
        let Some(run) = &self.run else {
            return;
        };
        let items: Vec<ListItem> = run
            .stages
            .iter()
            .map(|(stage, status, summary)| {
                let mut text = format!("{} {}", status.glyph(), stage.title());
                if !summary.is_empty() {
                    text.push_str(&format!(" — {summary}"));
                }
                ListItem::new(text)
            })
            .collect();
        frame.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title("Stages")),
            body[0],
        );
        let log_text: Vec<Line> = run
            .log
            .iter()
            .rev()
            .take(body[1].height.saturating_sub(2) as usize)
            .rev()
            .cloned()
            .map(Line::from)
            .collect();
        frame.render_widget(
            Paragraph::new(log_text)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title("Log")),
            body[1],
        );
        let status = if let Some(note) = &run.note {
            format!("note: {note}  (Enter: approve with note · Esc: back)")
        } else if run.approval_pending {
            "PLAN APPROVAL — [a]pprove · [e]dit note · [x] reject".to_string()
        } else if let Some(outcome) = &run.outcome {
            format!("{}  (q: quit · r: new run)", outcome.describe())
        } else {
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
            let mark = spinner[(run.elapsed_ticks as usize / 3) % spinner.len()];
            format!(
                "{mark} running… {}.{}s elapsed · x: abort",
                run.elapsed_ticks / 10,
                run.elapsed_ticks % 10
            )
        };
        frame.render_widget(
            Paragraph::new(status)
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Status")),
            chunks[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::mpsc::channel;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn fixture_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-tui-ui-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn first_screen_renders_the_picker() {
        let dir = fixture_dir("render");
        let app = App::new(dir.clone());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
        terminal.draw(|frame| app.draw(frame)).expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("clean-room rebuild workflow"), "{text}");
        assert!(text.contains("Target directory"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirming_a_valid_directory_reaches_configure() {
        let dir = fixture_dir("confirm");
        let mut app = App::new(dir.clone());
        app.picker.input_active = false;
        app.on_key(key(KeyCode::Char('c')), None, &AtomicBool::new(false));
        assert_eq!(app.screen, Screen::Configure);
        let form = app.form.as_ref().expect("form built");
        assert_eq!(form.target, dir.canonicalize().unwrap_or(dir.clone()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirming_a_missing_directory_shows_an_error_and_stays() {
        let dir = fixture_dir("missing");
        let mut app = App::new(dir.clone());
        app.picker.input = "/nonexistent-fathom-picker-target".to_string();
        app.on_key(key(KeyCode::Enter), None, &AtomicBool::new(false));
        assert_eq!(app.screen, Screen::PickDir);
        assert!(app.picker.error.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn required_mcp_cannot_be_unchecked() {
        let dir = fixture_dir("locked");
        let mut app = App::new(dir.clone());
        app.picker.input_active = false;
        app.on_key(key(KeyCode::Char('c')), None, &AtomicBool::new(false));
        {
            let form = app.form.as_mut().expect("form");
            form.focus = FormFocus::Mcps;
            form.mcp_cursor = KNOWN_MCPS.iter().position(|n| *n == "fathom").expect("row");
        }
        app.on_key(key(KeyCode::Char(' ')), None, &AtomicBool::new(false));
        let form = app.form.as_ref().expect("form");
        let row = KNOWN_MCPS.iter().position(|n| *n == "fathom").expect("row");
        assert!(form.mcp_checked[row], "fathom must stay checked");
        assert!(form.error.is_some(), "the refusal must be visible");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_produces_a_validated_run_request() {
        let dir = fixture_dir("start");
        let mut app = App::new(dir.clone());
        app.picker.input_active = false;
        app.on_key(key(KeyCode::Char('c')), None, &AtomicBool::new(false));
        app.form.as_mut().expect("form").focus = FormFocus::Start;
        app.on_key(key(KeyCode::Enter), None, &AtomicBool::new(false));
        assert_eq!(app.screen, Screen::Run);
        let config = app.take_start_request().expect("start requested");
        assert_eq!(config.target_dir, dir.canonicalize().unwrap_or(dir.clone()));
        assert!(config.mcps.contains("fathom"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_view_tracks_events_and_answers_approval() {
        let dir = fixture_dir("runview");
        let mut app = App::new(dir.clone());
        app.run = Some(RunView::new());
        app.screen = Screen::Run;
        app.on_workflow_event(WorkflowEvent::StageStarted {
            stage: Stage::Census,
        });
        app.on_workflow_event(WorkflowEvent::StageFinished {
            stage: Stage::Census,
            status: StageStatus::Done,
            summary: "3 files".to_string(),
        });
        app.on_workflow_event(WorkflowEvent::ApprovalRequested {
            plan_path: dir.join("plan.md"),
            stage: Stage::Plan,
        });
        let run = app.run.as_ref().expect("run view");
        assert_eq!(run.stages[0].1, StageStatus::Done);
        assert!(run.approval_pending);
        let (tx, rx) = channel::<ApprovalDecision>();
        app.on_key(key(KeyCode::Char('a')), Some(&tx), &AtomicBool::new(false));
        assert_eq!(rx.recv().expect("decision"), ApprovalDecision::Approve);
        assert!(!app.run.as_ref().expect("run view").approval_pending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_screen_renders_stages_and_outcome() {
        let dir = fixture_dir("runrender");
        let mut app = App::new(dir.clone());
        app.run = Some(RunView::new());
        app.screen = Screen::Run;
        app.on_workflow_event(WorkflowEvent::RunFinished {
            outcome: RunOutcome::StoppedAtRungBoundary {
                stage: Stage::Build,
            },
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
        terminal.draw(|frame| app.draw(frame)).expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("Census"), "{text}");
        assert!(text.contains("Translate"), "{text}");
        assert!(text.contains("rung 2"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
