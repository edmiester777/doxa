//! One frame: the header, the stacked panes, and the key hints.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::Frame;
use unicode_width::UnicodeWidthChar;

use super::state::{Entry, Mode, State};

pub const KEYS: &[(&str, &str)] = &[
    ("q  Ctrl-C", "stop everything; again to stop now"),
    ("Tab  Shift-Tab  1-9", "focus a pane"),
    ("↑ ↓  j k  PgUp PgDn", "scroll the focused pane"),
    ("Home g", "oldest line"),
    ("End  G  f", "newest line, and follow"),
    ("Enter  z", "zoom the focused pane; Esc returns"),
    ("r", "rebuild and restart the focused pane"),
    ("c", "clear the focused pane"),
    ("/", "filter the focused pane; Esc clears"),
    ("m", "mouse capture on/off (off lets you select text)"),
    (
        "mouse",
        "click focuses, wheel scrolls, double-click a title zooms, drag a title resizes",
    ),
    ("?", "this help"),
];

pub fn draw(f: &mut Frame, s: &mut State) {
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(f.area());
    header(f, head, s);
    let shown: Vec<usize> = match s.zoom {
        true => vec![s.focus],
        false => (0..s.order.len()).collect(),
    };
    let areas = Layout::vertical(
        shown
            .iter()
            .map(|&o| Constraint::Fill(s.panes[s.order[o]].weight)),
    )
    .split(body);
    s.rects = shown.iter().copied().zip(areas.iter().copied()).collect();
    for &(o, area) in &s.rects {
        pane(f, area, s, o);
    }
    footer(f, foot, s);
    if s.mode == Mode::Help {
        help(f);
    }
}

fn header(f: &mut Frame, area: Rect, s: &State) {
    let line = Line::from(vec![
        Span::raw(" doxa dev ").bold().reversed(),
        Span::raw("  "),
        Span::raw(s.header.join("  ·  ")),
    ]);
    f.render_widget(line, area);
    let mut right = Vec::new();
    if !s.mouse {
        right.push(Span::raw("mouse off (m) ").dark_gray());
    }
    match s.stops {
        0 => {}
        1 => right.push(Span::raw("stopping… q again to stop now ").yellow()),
        _ => right.push(Span::raw("stopping now ").yellow()),
    }
    f.render_widget(Line::from(right).right_aligned(), area);
}

fn pane(f: &mut Frame, area: Rect, s: &State, o: usize) {
    let focused = o == s.focus;
    let p = &s.panes[s.order[o]];
    let (label, color) = p.status.label();
    let name = Span::raw(format!(" {} {} ", o + 1, p.name)).bold();
    let name = match focused {
        true => name.black().on_cyan(),
        false => name,
    };
    let title = Line::from(vec![
        name,
        Span::raw(" "),
        Span::styled(label, Style::new().fg(color)),
        Span::raw(" "),
    ]);
    let mut right = Vec::new();
    if let Some(filter) = &p.filter {
        right.push(Span::raw(format!(" /{filter} ")).magenta());
    }
    if p.scroll > 0 {
        right.push(Span::raw(format!(" ↑{} ", p.scroll)).yellow());
    }
    let border = Style::new().fg(match focused {
        true => Color::Cyan,
        false => Color::DarkGray,
    });
    let block = Block::new()
        .borders(Borders::TOP)
        .border_style(border)
        .title(title)
        .title(Line::from(right).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);
    let shown = p.shown();
    // The last column is the scrollbar's, so lines don't rewrap as it comes and goes.
    let width = usize::from(inner.width.saturating_sub(1));
    let rows = tail(&shown, p.scroll, width, usize::from(inner.height));
    f.render_widget(Paragraph::new(Text::from(rows)), inner);
    if p.scroll > 0 {
        let mut bar = ScrollbarState::new(shown.len()).position(shown.len() - 1 - p.scroll);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            inner,
            &mut bar,
        );
    }
}

/// The rows that fill `height`, ending `scroll` lines back from the newest.
fn tail(shown: &[&Entry], scroll: usize, width: usize, height: usize) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    let end = shown.len().saturating_sub(scroll);
    for e in shown[..end].iter().rev() {
        for row in wrap(&e.line, width).into_iter().rev() {
            if rows.len() == height {
                break;
            }
            rows.push(row);
        }
        if rows.len() == height {
            break;
        }
    }
    rows.reverse();
    rows
}

/// `line` cut into rows of at most `width` columns, styles kept.
fn wrap(line: &Line<'static>, width: usize) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    let mut row: Vec<Span<'static>> = Vec::new();
    let mut used = 0;
    for span in &line.spans {
        let mut buf = String::new();
        for ch in span.content.chars() {
            let w = ch.width().unwrap_or(0);
            if used + w > width && used > 0 {
                row.push(Span::styled(std::mem::take(&mut buf), span.style));
                rows.push(Line::from(std::mem::take(&mut row)));
                used = 0;
            }
            buf.push(ch);
            used += w;
        }
        if !buf.is_empty() {
            row.push(Span::styled(buf, span.style));
        }
    }
    rows.push(Line::from(row));
    rows
}

fn footer(f: &mut Frame, area: Rect, s: &State) {
    let line = match s.mode {
        Mode::Filter => {
            let text = s.panes[s.order[s.focus]].filter.clone().unwrap_or_default();
            Line::from(vec![
                Span::raw(" filter: ").magenta(),
                Span::raw(text),
                Span::raw("▏").magenta(),
                Span::raw("   Enter keep · Esc clear").dark_gray(),
            ])
        }
        Mode::Help => Line::from(" any key closes help".dark_gray()),
        Mode::Normal => {
            let hint = [
                ("q", "quit"),
                ("tab", "focus"),
                ("↑↓", "scroll"),
                ("end", "follow"),
                ("enter", "zoom"),
                ("r", "restart"),
                ("c", "clear"),
                ("/", "filter"),
                ("m", "mouse"),
                ("?", "help"),
            ];
            Line::from(
                hint.iter()
                    .flat_map(|(k, d)| {
                        [
                            Span::raw(format!(" {k}")).bold(),
                            Span::raw(format!(" {d} ")).dark_gray(),
                        ]
                    })
                    .collect::<Vec<_>>(),
            )
        }
    };
    f.render_widget(line, area);
}

fn help(f: &mut Frame) {
    let width = 80.min(f.area().width);
    let height = (KEYS.len() as u16 + 2).min(f.area().height);
    let area = Rect {
        x: (f.area().width - width) / 2,
        y: (f.area().height - height) / 2,
        width,
        height,
    };
    let lines: Vec<Line> = KEYS
        .iter()
        .map(|(k, d)| Line::from(vec![Span::raw(format!(" {k:<22}")).bold(), Span::raw(*d)]))
        .collect();
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" keys ")),
        area,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::style::Color;

    use super::*;

    #[test]
    fn wrapping_splits_at_the_width_and_keeps_each_style() {
        let line = Line::from(vec![Span::raw("abc").red(), Span::raw("defg")]);
        let rows = wrap(&line, 4);
        let text: Vec<String> = rows.iter().map(|r| r.to_string()).collect();
        assert_eq!(text, ["abcd", "efg"]);
        assert_eq!(rows[0].spans[0].style.fg, Some(Color::Red));
        assert_eq!(rows[0].spans[1].style.fg, None);
        assert_eq!(wrap(&Line::raw(""), 4).len(), 1);
    }
}
