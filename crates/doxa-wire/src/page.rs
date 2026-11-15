//! Paged listings: `?page=2&page_size=50` in, a [`Page`] out.

use serde::{Deserialize, Serialize};

/// Which page of a listing to answer: `page` from 1, `page_size` within `1..=MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageInput<const MAX: u32 = 200> {
    /// The page to answer, from 1. Default: 1.
    #[serde(default = "first")]
    pub page: u32,
    /// Items per page, at most `MAX`. Default: [`DEFAULT_PAGE_SIZE`].
    #[serde(default = "default_size")]
    pub page_size: u32,
}

/// The size a request that names none gets.
pub const DEFAULT_PAGE_SIZE: u32 = 20;

fn first() -> u32 {
    1
}

fn default_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

impl<const MAX: u32> Default for PageInput<MAX> {
    fn default() -> Self {
        Self::new(1, DEFAULT_PAGE_SIZE)
    }
}

impl<const MAX: u32> PageInput<MAX> {
    /// Page `page` (from 1) of `page_size` items.
    pub const fn new(page: u32, page_size: u32) -> Self {
        Self { page, page_size }
    }

    /// The page answered: `page`, or 1 for 0.
    pub fn number(&self) -> u32 {
        self.page.max(1)
    }

    /// The size answered: `page_size` within `1..=MAX`, so an unvalidated request is cut, not refused.
    pub fn size(&self) -> u32 {
        self.page_size.clamp(1, MAX)
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

#[cfg(feature = "garde")]
impl<const MAX: u32> garde::Validate for PageInput<MAX> {
    type Context = ();

    fn validate_into(
        &self,
        _: &(),
        parent: &mut dyn FnMut() -> garde::Path,
        report: &mut garde::Report,
    ) {
        if self.page < 1 {
            report.append(
                parent().join("page"),
                garde::Error::new("must be at least 1"),
            );
        }
        if !(1..=MAX).contains(&self.page_size) {
            report.append(
                parent().join("page_size"),
                garde::Error::new(format!("must be between 1 and {MAX}")),
            );
        }
    }
}

#[cfg(feature = "utoipa")]
mod docs {
    use utoipa::openapi::path::{Parameter, ParameterBuilder, ParameterIn};
    use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};
    use utoipa::openapi::{KnownFormat, RefOr, Required, SchemaFormat};

    use super::{PageInput, DEFAULT_PAGE_SIZE};

    fn field(minimum: u32, maximum: Option<u32>, default: u32, about: &str) -> ObjectBuilder {
        ObjectBuilder::new()
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int32)))
            .minimum(Some(minimum))
            .maximum(maximum)
            .default(Some(default.into()))
            .description(Some(about))
    }

    fn fields<const MAX: u32>() -> [(&'static str, ObjectBuilder); 2] {
        [
            ("page", field(1, None, 1, "The page to answer, from 1.")),
            (
                "page_size",
                field(1, Some(MAX), DEFAULT_PAGE_SIZE, "Items per page."),
            ),
        ]
    }

    impl<const MAX: u32> utoipa::IntoParams for PageInput<MAX> {
        fn into_params(at: impl Fn() -> Option<ParameterIn>) -> Vec<Parameter> {
            fields::<MAX>()
                .into_iter()
                .map(|(name, schema)| {
                    ParameterBuilder::new()
                        .name(name)
                        .required(Required::False)
                        .parameter_in(at().unwrap_or(ParameterIn::Query))
                        .schema(Some(schema))
                        .build()
                })
                .collect()
        }
    }

    impl<const MAX: u32> utoipa::PartialSchema for PageInput<MAX> {
        fn schema() -> RefOr<Schema> {
            fields::<MAX>()
                .into_iter()
                .fold(ObjectBuilder::new(), |object, (name, schema)| {
                    object.property(name, schema)
                })
                .into()
        }
    }

    impl<const MAX: u32> utoipa::ToSchema for PageInput<MAX> {}
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
    pub fn new<const MAX: u32>(items: Vec<T>, input: &PageInput<MAX>, total: u64) -> Self {
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
    pub fn of<const MAX: u32>(all: impl IntoIterator<Item = T>, input: &PageInput<MAX>) -> Self {
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
    pub fn next<const MAX: u32>(&self) -> Option<PageInput<MAX>> {
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
        assert_eq!(input, PageInput::new(1, DEFAULT_PAGE_SIZE));
        let input: PageInput = serde_json::from_str(r#"{"page":3}"#).unwrap();
        assert_eq!(input.offset(), 40);
    }

    #[test]
    fn a_size_past_the_maximum_is_cut_to_it() {
        let input = PageInput::<100>::new(0, 10_000);
        let page = Page::new(Vec::<u8>::new(), &input, 250);
        assert_eq!((page.page, page.page_size, page.total_pages), (1, 100, 3));
        assert_eq!(PageInput::<200>::new(1, 10_000).size(), 200);
    }

    #[test]
    fn a_listing_in_memory_is_cut_to_the_page() {
        let page = Page::of(1..=25, &PageInput::<200>::new(3, 10));
        assert_eq!(page.items, vec![21, 22, 23, 24, 25]);
        assert_eq!((page.total, page.total_pages), (25, 3));
        assert!(!page.has_next());
        assert_eq!(
            Page::of(1..=25, &PageInput::<200>::new(1, 10)).next(),
            Some(PageInput::<200>::new(2, 10))
        );
    }

    #[test]
    fn no_items_is_no_pages() {
        let page = Page::of(Vec::<u8>::new(), &PageInput::<200>::default());
        assert_eq!((page.total, page.total_pages), (0, 0));
        assert!(page.next::<200>().is_none());
    }

    #[cfg(feature = "garde")]
    #[test]
    fn validation_refuses_page_zero_and_a_size_past_the_maximum() {
        use garde::Validate;
        assert!(PageInput::<50>::new(1, 50).validate().is_ok());
        let report = PageInput::<50>::new(0, 51).validate().unwrap_err();
        let paths: Vec<String> = report.iter().map(|(p, _)| p.to_string()).collect();
        assert_eq!(paths, ["page", "page_size"]);
    }
}
