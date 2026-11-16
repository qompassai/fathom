#![forbid(unsafe_code)]
//! The fathom-tui binary: a thin terminal shell over the
//! workflow engine.
//!
//! `main` owns the terminal (raw mode + alternate screen,
//! restored on every exit path), spawns the engine on a
//! worker thread per run, and pumps keys and typed workflow
//! events into the App. All state and rendering live in the
//! library.

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use fathom_tui::engine::Engine;
use fathom_tui::events::{ApprovalDecision, RunOutcome, WorkflowEvent};
use fathom_tui::tui::App;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

/// Input/event pump cadence; also the App tick unit (0.1 s).
const POLL_MS: u64 = 100;

fn main() -> io::Result<()> {
    let initial = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, App::new(initial));
    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// Per-run wiring: fresh channels per run so a finished run's
/// channels are never reused.
struct RunChannels {
    approvals: Sender<ApprovalDecision>,
    events: Receiver<WorkflowEvent>,
    handle: JoinHandle<RunOutcome>,
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, mut app: App) -> io::Result<()> {
    let abort = Arc::new(AtomicBool::new(false));
    let mut channels: Option<RunChannels> = None;
    loop {
        terminal.draw(|frame| app.draw(frame))?;
        if let Some(config) = app.take_start_request() {
            abort.store(false, Ordering::SeqCst);
            match Engine::new(config) {
                Ok(engine) => {
                    let (event_tx, event_rx) = channel::<WorkflowEvent>();
                    let (approval_tx, approval_rx) = channel::<ApprovalDecision>();
                    let engine_abort = Arc::clone(&abort);
                    let handle =
                        std::thread::spawn(move || engine.run(event_tx, approval_rx, engine_abort));
                    channels = Some(RunChannels {
                        approvals: approval_tx,
                        events: event_rx,
                        handle,
                    });
                }
                Err(error) => {
                    if let Some(form) = &mut app.form {
                        form.error = Some(error.to_string());
                    }
                    app.screen = fathom_tui::tui::Screen::Configure;
                }
            }
        }
        if let Some(active) = &channels {
            while let Ok(event) = active.events.try_recv() {
                app.on_workflow_event(event);
            }
        }
        if event::poll(Duration::from_millis(POLL_MS))?
            && let Event::Key(key) = event::read()?
        {
            let approvals = channels.as_ref().map(|active| &active.approvals);
            app.on_key(key, approvals, &abort);
        }
        app.tick();
        if app.quit {
            abort.store(true, Ordering::SeqCst);
            if let Some(active) = channels.take() {
                let _ = active.handle.join();
            }
            return Ok(());
        }
    }
}
