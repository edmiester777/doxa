use std::future::IntoFuture;

use doxa_wire::{Page, PageInput};

/// Every item of a paged listing, fetched `MAX` at a time until the last.
///
/// ```ignore
/// let all = doxa::client::every_page(|page| list_widgets(page, Filter::default())).await?;
/// ```
pub async fn every_page<const MAX: u32, T, E, F, C>(mut call: F) -> Result<Vec<T>, E>
where
    F: FnMut(PageInput<MAX>) -> C,
    C: IntoFuture<Output = Result<Page<T>, E>>,
{
    let mut input = PageInput::new(1, MAX);
    let mut all = Vec::new();
    loop {
        let page = call(input).await?;
        let next = page.next();
        all.extend(page.items);
        match next {
            Some(n) => input = n,
            None => return Ok(all),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_is_fetched_once() {
        let mut asked = Vec::new();
        let all = futures::executor::block_on(every_page(|input: PageInput<100>| {
            asked.push((input.page, input.page_size));
            std::future::ready(Ok::<_, ()>(Page::of(1..=250, &input)))
        }))
        .unwrap();
        assert_eq!(all.len(), 250);
        assert_eq!(asked, [(1, 100), (2, 100), (3, 100)]);
    }
}
