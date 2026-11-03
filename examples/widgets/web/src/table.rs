//! A table over any row type; `<Table rows={…} …/>` infers it.

use doxa::ui::prelude::*;

/// A header, and how to read one row's cell.
pub struct Column<T> {
    pub header: &'static str,
    pub cell: fn(&T) -> String,
}

impl<T> Clone for Column<T> {
    fn clone(&self) -> Self {
        Column {
            header: self.header,
            cell: self.cell,
        }
    }
}

#[component]
pub fn Table<T: Clone + 'static>(
    rows: Vec<T>,
    columns: Vec<Column<T>>,
    row_key: fn(&T) -> String,
) -> View {
    let head: View = columns
        .iter()
        .map(|c| view! { <th>{c.header}</th> })
        .collect();
    let body: View = rows
        .iter()
        .map(|r| {
            let cells: View = columns
                .iter()
                .map(|c| view! { <td>{(c.cell)(r)}</td> })
                .collect();
            view! { <tr key={row_key(r)}>{cells}</tr> }
        })
        .collect();
    view! {
        <table>
            <thead>
                <tr>{head}</tr>
            </thead>
            <tbody>{body}</tbody>
        </table>
    }
}
