//! Progress for the person at the terminal.
//!
//! A command that takes time tells what it is doing on the error output, so that the
//! output of the command (the result) stays clean for a script. There are three ways to
//! show it ([`ProgressMode`]):
//!
//! - **Live** (the error output is a terminal): one line that is redrawn in place.
//! - **Heartbeat** (a pipe, a file, a scheduled job): a new line at long intervals, so a
//!   log shows that the run is alive.
//! - **Off**: nothing.
//!
//! A command that ends quickly shows nothing at all. The first line comes after half a
//! second (live) or after the first interval (heartbeat).
//!
//! The commands wait in calls that report nothing for a long time (the scan of the packs
//! of a large vault, the walk of a large folder). So a thread of the reporter looks at
//! the clock, and redraws the line with the elapsed time. The line is never silent for
//! longer than a second.
//!
//! A line has numbers and fixed words only. It never has a file name, a title or
//! content (AGENTS.md).

use crate::display::{size, span};
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// The first live line comes after this time.
const FIRST_LIVE_LINE_AFTER: Duration = Duration::from_millis(500);
/// A live line is drawn at most this often.
const LIVE_LINE_EVERY: Duration = Duration::from_millis(100);
/// The speed is measured over this time.
const WINDOW: Duration = Duration::from_secs(30);
/// The speed is measured at this interval.
const SAMPLE_EVERY: Duration = Duration::from_millis(250);
/// The estimate of the time that is left comes after this time of measuring.
const ESTIMATE_AFTER: Duration = Duration::from_secs(5);
/// A line that has no numbers shows the time that the step takes after this time.
const SHOW_ELAPSED_AFTER: Duration = Duration::from_secs(2);
/// A live line has at most this number of characters, so that it does not wrap on a
/// terminal of the usual width.
const MAX_LINE: usize = 79;
/// The thread looks at the clock at least this often.
const SHORTEST_TICK: Duration = Duration::from_millis(50);
const LONGEST_TICK: Duration = Duration::from_secs(1);

/// How a command shows its progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProgressMode {
    /// Show nothing.
    #[default]
    Off,
    /// A line that is redrawn in place, for a terminal.
    Live,
    /// A new line after each interval, for a log.
    Heartbeat(Duration),
}

/// What a command is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The step, in a few words.
    pub label: &'static str,
    /// The items that are done and the items that there are.
    pub items: Option<(u64, u64)>,
    /// The bytes that are done, and the bytes that there are when that is known.
    pub bytes: Option<(u64, Option<u64>)>,
}

impl Status {
    /// A step without numbers.
    pub fn step(label: &'static str) -> Self {
        Self {
            label,
            items: None,
            bytes: None,
        }
    }

    /// A step that counts items.
    pub fn items(label: &'static str, done: u64, total: u64) -> Self {
        Self {
            label,
            items: Some((done, total)),
            bytes: None,
        }
    }

    /// A step that counts items and bytes.
    pub fn transfer(
        label: &'static str,
        items: (u64, u64),
        bytes_done: u64,
        bytes_total: Option<u64>,
    ) -> Self {
        Self {
            label,
            items: Some(items),
            bytes: Some((bytes_done, bytes_total)),
        }
    }

    /// The count that the percentage and the estimate follow: bytes when the total is
    /// known (a large file takes more time than a small one), else items.
    fn primary(&self) -> Option<(u64, u64)> {
        match (self.bytes, self.items) {
            (Some((done, Some(total))), _) if total > 0 => Some((done.min(total), total)),
            (_, Some((done, total))) if total > 0 => Some((done.min(total), total)),
            _ => None,
        }
    }
}

/// The part of the reporter that decides what to show. It gets the time as an argument, so
/// that a test can give its own.
struct Inner<'a> {
    err: &'a mut (dyn Write + Send),
    mode: ProgressMode,
    status: Option<Status>,
    /// The time of the first status. A line is never shown before the first delay of it.
    first_seen: Duration,
    /// The time at which the step began.
    step_began: Duration,
    /// The time of the last line.
    last_shown: Option<Duration>,
    /// The last line that a live display drew, and how wide it was.
    drawn: String,
    /// The measurements of the speed: the time and the count.
    samples: VecDeque<(Duration, u64)>,
    samples_total: u64,
}

impl<'a> Inner<'a> {
    fn new(err: &'a mut (dyn Write + Send), mode: ProgressMode) -> Self {
        Self {
            err,
            mode,
            status: None,
            first_seen: Duration::ZERO,
            step_began: Duration::ZERO,
            last_shown: None,
            drawn: String::new(),
            samples: VecDeque::new(),
            samples_total: 0,
        }
    }

    /// The command says what it is doing now.
    fn update(&mut self, now: Duration, status: Status) {
        if self.status.is_none() {
            self.first_seen = now;
            self.step_began = now;
        }
        let new_step = self
            .status
            .as_ref()
            .is_some_and(|before| before.label != status.label);
        if new_step {
            self.step_began = now;
        }
        self.measure(now, &status);
        self.status = Some(status);
        self.show_if_due(now, new_step);
    }

    /// Time passes without news.
    fn tick(&mut self, now: Duration) {
        self.show_if_due(now, false);
    }

    /// Keeps the measurements of the speed.
    fn measure(&mut self, now: Duration, status: &Status) {
        let Some((done, total)) = status.primary() else {
            self.samples.clear();
            self.samples_total = 0;
            return;
        };
        // Another total or a count that went back: it is another job, so measure again.
        let went_back = self
            .samples
            .back()
            .is_some_and(|&(_, before)| done < before);
        if total != self.samples_total || went_back {
            self.samples.clear();
            self.samples_total = total;
        }
        if self
            .samples
            .back()
            .is_none_or(|&(time, _)| now.saturating_sub(time) >= SAMPLE_EVERY)
        {
            self.samples.push_back((now, done));
        }
        // Keep one measurement from before the window: the speed is over the window.
        while self.samples.len() > 2 && now.saturating_sub(self.samples[1].0) > WINDOW {
            self.samples.pop_front();
        }
    }

    /// The time that is left, when the speed is known well enough.
    fn time_left(&self, now: Duration, done: u64, total: u64) -> Option<Duration> {
        let &(began, before) = self.samples.front()?;
        let measured = now.saturating_sub(began);
        if measured < ESTIMATE_AFTER || done <= before || done >= total {
            return None;
        }
        let per_second = (done - before) as f64 / measured.as_secs_f64();
        let seconds = (total - done) as f64 / per_second;
        // A number that does not mean anything is not shown.
        (seconds.is_finite() && seconds < 100.0 * 3600.0).then(|| Duration::from_secs_f64(seconds))
    }

    /// The text of the line for the status now.
    fn line(&self, now: Duration) -> Option<String> {
        let status = self.status.as_ref()?;
        let mut parts: Vec<String> = Vec::new();
        if let Some((done, total)) = status.items {
            parts.push(format!("{done} / {total} items"));
        }
        match status.bytes {
            Some((done, Some(total))) => {
                parts.push(format!("{} / {}", size(done), size(total.max(done))));
            }
            Some((done, None)) => parts.push(size(done)),
            None => {}
        }
        if let Some((done, total)) = status.primary() {
            // `u128`: a count near the limit of `u64` must not overflow.
            parts.push(format!("{}%", u128::from(done) * 100 / u128::from(total)));
            if let Some(left) = self.time_left(now, done, total) {
                parts.push(format!("about {} left", span(left)));
            }
        }
        if parts.is_empty() {
            let elapsed = now.saturating_sub(self.step_began);
            return Some(if elapsed >= SHOW_ELAPSED_AFTER {
                format!("{}... {}", status.label, span(elapsed))
            } else {
                format!("{}...", status.label)
            });
        }
        Some(format!("{}: {}", status.label, parts.join(", ")))
    }

    fn show_if_due(&mut self, now: Duration, new_step: bool) {
        let due = match self.mode {
            ProgressMode::Off => false,
            ProgressMode::Live => {
                now.saturating_sub(self.first_seen) >= FIRST_LIVE_LINE_AFTER
                    && (new_step
                        || self
                            .last_shown
                            .is_none_or(|time| now.saturating_sub(time) >= LIVE_LINE_EVERY))
            }
            ProgressMode::Heartbeat(every) => {
                now.saturating_sub(self.last_shown.unwrap_or(self.first_seen)) >= every
            }
        };
        if !due {
            return;
        }
        let Some(line) = self.line(now) else {
            return;
        };
        self.last_shown = Some(now);
        match self.mode {
            ProgressMode::Off => {}
            ProgressMode::Live => self.draw(line),
            ProgressMode::Heartbeat(_) => {
                let _ = writeln!(self.err, "{line}");
                let _ = self.err.flush();
            }
        }
    }

    /// Draws a line over the one before it. A terminal needs no control codes for this:
    /// the cursor goes back to the start, and spaces cover what is left of a longer line.
    fn draw(&mut self, line: String) {
        let line: String = line.chars().take(MAX_LINE).collect();
        if line == self.drawn {
            return;
        }
        let cover = self
            .drawn
            .chars()
            .count()
            .saturating_sub(line.chars().count());
        let _ = write!(self.err, "\r{line}{}\r", " ".repeat(cover));
        let _ = self.err.flush();
        self.drawn = line;
    }

    /// Takes the line away, so that the output after it starts on a clean line.
    fn clear(&mut self) {
        if !self.drawn.is_empty() {
            let blank = " ".repeat(self.drawn.chars().count());
            let _ = write!(self.err, "\r{blank}\r");
            let _ = self.err.flush();
            self.drawn.clear();
        }
    }
}

struct Shared<'a> {
    inner: Mutex<Inner<'a>>,
    stopped: Mutex<bool>,
    wake: Condvar,
    start: Instant,
}

/// What a command uses to tell what it is doing. It can be used from any thread.
pub struct Reporter<'s, 'a> {
    shared: Option<&'s Shared<'a>>,
}

impl Reporter<'_, '_> {
    /// Tells what the command is doing now. It is quick, so that a command can call it
    /// often: it shows a line only when one is due.
    pub fn report(&self, status: Status) {
        if let Some(shared) = self.shared {
            let now = shared.start.elapsed();
            if let Ok(mut inner) = shared.inner.lock() {
                inner.update(now, status);
            }
        }
    }
}

/// Runs `work` with a reporter that shows its progress on `err`. The line is gone when
/// `work` ends, and `err` is free again, so that the command can write its own messages.
pub fn with_reporter<T>(
    err: &mut (dyn Write + Send),
    mode: ProgressMode,
    work: impl FnOnce(&Reporter<'_, '_>) -> T,
) -> T {
    if mode == ProgressMode::Off {
        return work(&Reporter { shared: None });
    }
    let tick = match mode {
        ProgressMode::Heartbeat(every) => every.clamp(SHORTEST_TICK, LONGEST_TICK),
        _ => LIVE_LINE_EVERY,
    };
    let shared = Shared {
        inner: Mutex::new(Inner::new(err, mode)),
        stopped: Mutex::new(false),
        wake: Condvar::new(),
        start: Instant::now(),
    };
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            let Ok(mut stopped) = shared.stopped.lock() else {
                return;
            };
            loop {
                let Ok((guard, _)) = shared.wake.wait_timeout_while(stopped, tick, |s| !*s) else {
                    return;
                };
                stopped = guard;
                if *stopped {
                    return;
                }
                if let Ok(mut inner) = shared.inner.lock() {
                    inner.tick(shared.start.elapsed());
                }
            }
        });
        // The thread must stop also when `work` panics, or the scope never ends.
        struct Stop<'x, 'y>(&'x Shared<'y>);
        impl Drop for Stop<'_, '_> {
            fn drop(&mut self) {
                if let Ok(mut stopped) = self.0.stopped.lock() {
                    *stopped = true;
                }
                self.0.wake.notify_all();
            }
        }
        let _stop = Stop(&shared);
        work(&Reporter {
            shared: Some(&shared),
        })
    });
    if let Ok(mut inner) = shared.inner.lock() {
        inner.clear();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: f64) -> Duration {
        Duration::from_secs_f64(n)
    }

    fn text(out: &[u8]) -> String {
        String::from_utf8(out.to_vec()).unwrap()
    }

    /// The text that the live display drew, line by line, without the control characters.
    fn lines(out: &[u8]) -> Vec<String> {
        text(out)
            .split('\r')
            .map(|part| part.trim_end().to_string())
            .filter(|part| !part.is_empty())
            .collect()
    }

    #[test]
    fn a_command_that_ends_quickly_shows_nothing() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(secs(0.0), Status::step("Opening the vault"));
        inner.update(secs(0.2), Status::items("Reading", 1, 10));
        inner.tick(secs(0.4));
        inner.clear();
        assert!(out.is_empty());
    }

    #[test]
    fn a_step_without_numbers_shows_the_time_that_it_takes() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(secs(0.0), Status::step("Opening the vault"));
        inner.tick(secs(0.6));
        inner.tick(secs(1.0));
        inner.tick(secs(12.0));
        inner.tick(secs(75.0));
        assert_eq!(
            lines(&out),
            [
                "Opening the vault...",
                "Opening the vault... 12 s",
                "Opening the vault... 1 min 15 s"
            ]
        );
    }

    #[test]
    fn counts_and_percentage_follow_the_bytes_when_the_total_is_known() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        // Few items, but most of the bytes are in the first one.
        inner.update(
            secs(0.0),
            Status::transfer("Backing up", (0, 4), 0, Some(1000 * 1024)),
        );
        inner.update(
            secs(1.0),
            Status::transfer("Backing up", (1, 4), 750 * 1024, Some(1000 * 1024)),
        );
        assert_eq!(
            lines(&out),
            ["Backing up: 1 / 4 items, 750.0 KiB / 1000.0 KiB, 75%"]
        );
    }

    #[test]
    fn the_percentage_follows_the_items_when_the_bytes_have_no_total() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(secs(0.0), Status::transfer("Backing up", (0, 8), 0, None));
        inner.update(
            secs(1.0),
            Status::transfer("Backing up", (2, 8), 2048, None),
        );
        assert_eq!(lines(&out), ["Backing up: 2 / 8 items, 2.0 KiB, 25%"]);
    }

    #[test]
    fn a_count_above_the_total_does_not_pass_one_hundred_percent() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        // A file grew after the list was made.
        inner.update(
            secs(0.0),
            Status::transfer("Backing up", (1, 1), 2048, Some(1024)),
        );
        inner.update(
            secs(1.0),
            Status::transfer("Backing up", (1, 1), 2048, Some(1024)),
        );
        assert_eq!(
            lines(&out),
            ["Backing up: 1 / 1 items, 2.0 KiB / 2.0 KiB, 100%"]
        );
    }

    #[test]
    fn the_estimate_comes_after_a_few_seconds_of_measuring() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        // 10 items per second, 1000 items.
        for second in 0..=20 {
            let done = second * 10;
            inner.update(
                secs(second as f64),
                Status::items("Reading records", done, 1000),
            );
        }
        let all = lines(&out);
        let at = |done: &str| {
            all.iter()
                .find(|line| line.starts_with(&format!("Reading records: {done} / ")))
                .unwrap()
                .as_str()
        };
        // At 3 seconds: too early.
        assert_eq!(at("30"), "Reading records: 30 / 1000 items, 3%");
        // At 10 seconds: 100 done, 900 to go, 90 seconds.
        assert_eq!(
            at("100"),
            "Reading records: 100 / 1000 items, 10%, about 1 min 30 s left"
        );
        assert_eq!(
            at("200"),
            "Reading records: 200 / 1000 items, 20%, about 1 min 20 s left"
        );
    }

    #[test]
    fn the_speed_is_the_speed_of_the_last_seconds() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        // 1 item per second for 60 seconds, then 100 items per second.
        let mut done = 0;
        for second in 0..=90 {
            done += if second <= 60 { 1 } else { 100 };
            inner.update(secs(second as f64), Status::items("Reading", done, 10_000));
        }
        // 90 seconds in: 3061 done. The window of 30 seconds says about 100 per second,
        // so about 70 seconds are left. The speed over the whole run (about 34 per
        // second) would say about 200 seconds.
        let left = inner.time_left(secs(90.0), done, 10_000).unwrap();
        assert!((65..80).contains(&left.as_secs()), "{left:?}");
    }

    #[test]
    fn a_new_total_starts_a_new_measurement() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        for second in 0..=10 {
            inner.update(secs(second as f64), Status::items("A", second * 10, 1000));
        }
        // Another job: no estimate until it has been measured for a few seconds.
        inner.update(secs(11.0), Status::items("B", 0, 50));
        inner.update(secs(12.0), Status::items("B", 5, 50));
        let last = lines(&out).pop().unwrap();
        assert_eq!(last, "B: 5 / 50 items, 10%");
    }

    #[test]
    fn a_line_is_not_drawn_again_when_it_has_not_changed() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(secs(0.0), Status::step("Opening the vault"));
        for tenth in 6..=15 {
            inner.tick(secs(tenth as f64 / 10.0));
        }
        assert_eq!(lines(&out), ["Opening the vault..."]);
    }

    #[test]
    fn a_shorter_line_covers_the_longer_one_and_the_end_takes_the_line_away() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(secs(0.0), Status::step("Reading the journal"));
        inner.tick(secs(1.0));
        inner.update(secs(2.0), Status::step("Done"));
        inner.clear();
        let all = text(&out);
        let (long, short) = ("Reading the journal...", "Done...");
        assert_eq!(
            all,
            format!(
                "\r{long}\r\r{short}{}\r\r{}\r",
                " ".repeat(long.len() - short.len()),
                " ".repeat(short.len())
            )
        );
        assert!(!all.contains('\n'));
    }

    #[test]
    fn a_live_line_is_not_longer_than_a_terminal_line() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Live);
        inner.update(
            secs(0.0),
            Status::transfer(
                "Backing up",
                (123_456_789, 987_654_321),
                u64::MAX / 4,
                Some(u64::MAX / 2),
            ),
        );
        inner.tick(secs(1.0));
        assert!(lines(&out)[0].chars().count() <= MAX_LINE);
    }

    #[test]
    fn a_heartbeat_is_a_line_at_each_interval() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Heartbeat(Duration::from_secs(30)));
        inner.update(secs(0.0), Status::step("Opening the vault"));
        for second in 1..=29 {
            inner.tick(secs(second as f64));
        }
        // Nothing before the first interval: the text below has no line of these seconds.
        inner.tick(secs(30.0));
        inner.update(secs(31.0), Status::items("Reading records", 10, 100));
        inner.update(secs(59.0), Status::items("Reading records", 50, 100));
        inner.update(secs(60.0), Status::items("Reading records", 60, 100));
        let shown = text(&out);
        assert_eq!(
            shown,
            "Opening the vault... 30 s\nReading records: 60 / 100 items, 60%, about 23 s left\n"
        );
        assert!(!shown.contains('\r'));
    }

    #[test]
    fn off_shows_nothing() {
        let mut out = Vec::new();
        let mut inner = Inner::new(&mut out, ProgressMode::Off);
        inner.update(secs(0.0), Status::step("Opening the vault"));
        inner.tick(secs(100.0));
        inner.clear();
        assert!(out.is_empty());
    }

    #[test]
    fn the_reporter_shows_what_the_command_reports_and_leaves_a_clean_line() {
        let mut out = Vec::new();
        let result = with_reporter(&mut out, ProgressMode::Heartbeat(Duration::ZERO), |r| {
            r.report(Status::items("Reading records", 3, 10));
            7
        });
        assert_eq!(result, 7);
        assert!(text(&out).contains("Reading records: 3 / 10 items, 30%\n"));
        // The error output is free again.
        out.extend_from_slice(b"next");
    }

    #[test]
    fn the_thread_shows_a_step_that_reports_nothing() {
        let mut out = Vec::new();
        with_reporter(&mut out, ProgressMode::Heartbeat(Duration::ZERO), |r| {
            r.report(Status::step("Opening the vault"));
            // The command waits. The thread must say that the step goes on.
            std::thread::sleep(Duration::from_millis(400));
        });
        let shown = text(&out);
        assert!(
            shown.lines().count() >= 2 && shown.lines().all(|l| l.starts_with("Opening")),
            "{shown}"
        );
    }

    #[test]
    fn no_mode_no_thread_and_no_output() {
        let mut out = Vec::new();
        let result = with_reporter(&mut out, ProgressMode::Off, |r| {
            r.report(Status::step("x"));
            1
        });
        assert_eq!((result, out.len()), (1, 0));
    }

    #[test]
    fn a_panic_of_the_command_does_not_hang_the_reporter() {
        let outcome = std::panic::catch_unwind(|| {
            let mut out = Vec::new();
            with_reporter(&mut out, ProgressMode::Live, |_| {
                panic!("the command failed")
            });
        });
        assert!(outcome.is_err());
    }
}
