//! Paged listings: `?page=2&page_size=50` in, a [`Page`] out.

use serde::{Deserialize, Serialize};

/// Which page of a listing to answer. `page` counts from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams, utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct PageInput {
    /// The page to answer, from 1. Default: 1.
    #[serde(default = "first")]
    pub page: u32,
    /// Items per page, at most [`PageInput::MAX_SIZE`]. Default: [`PageInput::DEFAULT_SIZE`].
    #[serde(default = "default_size")]
    pub page_size: u32,
}

fn first() -> u32 {
    1
}

fn default_size() -> u32 {
    PageInput::DEFAULT_SIZE
}

impl Default for PageInput {
    fn default() -> Self {
        Self::new(1, Self::DEFAULT_SIZE)
    }
}

impl PageInput {
    /// The size a request that names none gets.
    pub const DEFAULT_SIZE: u32 = 20;
    /// The largest size the server answers; a larger request gets this many.
    pub const MAX_SIZE: u32 = 100;

    /// Page `page` (from 1) of `page_size` items.
    pub const fn new(page: u32, page_size: u32) -> Self {
        Self { page, page_size }
    }

    /// The page answered: `page`, or 1 for 0.
    pub fn number(&self) -> u32 {
        self.page.max(1)
    }

    /// The size answered: `page_size` within `1..=MAX_SIZE`.
    pub fn size(&self) -> u32 {
        self.page_size.clamp(1, Self::MAX_SIZE)
    }

    /// How many items come before this page.
    pub fn offset(&self) -> u64 {
        u64::from(self.number() - 1) * u64::from(self.size())
    }

    /// The page after this one, the same size.
    pub fn next(&self) -> Self {
        Self::new(self.number().saturating_add(1), self.size())
    }
}

/// One page of a listing, and where it sits among the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Page<T> {
    /// This page's items.
    pub items: Vec<T>,
    /// This page's number, from 1.
    pub page: u32,
    /// The size each page is cut to; the last may hold fewer.
    pub page_size: u32,
    /// Items across every page.
    pub total: u64,
    /// Pages in all; 0 when there are no items.
    pub total_pages: u32,
}

impl<T> Page<T> {
    /// `items`, the page `input` asked for, out of `total`.
    pub fn new(items: Vec<T>, input: &PageInput, total: u64) -> Self {
        let size = input.size();
        let pages = total.div_ceil(u64::from(size));
        Self {
            items,
            page: input.number(),
            page_size: size,
            total,
            total_pages: u32::try_from(pages).unwrap_or(u32::MAX),
        }
    }

    /// The page `input` asks for, cut from a whole listing held in memory.
    pub fn of(all: impl IntoIterator<Item = T>, input: &PageInput) -> Self {
        let all: Vec<T> = all.into_iter().collect();
        let total = all.len() as u64;
        let skip = usize::try_from(input.offset()).unwrap_or(usize::MAX);
        let items = all
            .into_iter()
            .skip(skip)
            .take(input.size() as usize)
            .collect();
        Self::new(items, input, total)
    }

    /// Whether a page follows this one.
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }

    /// The request for the page after this one.
    pub fn next(&self) -> Option<PageInput> {
        self.has_next()
            .then(|| PageInput::new(self.page + 1, self.page_size))
    }

    /// The same page with each item converted.
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            page: self.page,
            page_size: self.page_size,
            total: self.total,
            total_pages: self.total_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_page_or_size_takes_the_default() {
        let input: PageInput = serde_json::from_str("{}").unwrap();
        assert_eq!(input, PageInput::new(1, PageInput::DEFAULT_SIZE));
        let input: PageInput = serde_json::from_str(r#"{"page":3}"#).unwrap();
        assert_eq!(input.offset(), 40);
    }

    #[test]
    fn a_size_past_the_maximum_is_cut_to_it() {
        let page = Page::new(Vec::<u8>::new(), &PageInput::new(0, 10_000), 250);
        assert_eq!((page.page, page.page_size, page.total_pages), (1, 100, 3));
    }

    #[test]
    fn a_listing_in_memory_is_cut_to_the_page() {
        let page = Page::of(1..=25, &PageInput::new(3, 10));
        assert_eq!(page.items, vec![21, 22, 23, 24, 25]);
        assert_eq!((page.total, page.total_pages), (25, 3));
        assert!(!page.has_next());
        assert_eq!(
            Page::of(1..=25, &PageInput::new(1, 10)).next(),
            Some(PageInput::new(2, 10))
        );
    }

    #[test]
    fn no_items_is_no_pages() {
        let page = Page::of(Vec::<u8>::new(), &PageInput::default());
        assert_eq!((page.total, page.total_pages), (0, 0));
        assert!(page.next().is_none());
    }
}
