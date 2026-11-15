//! `query.page(&db, &input)`: one page of a SeaORM query, and the total behind it.

use doxa_wire::{Page, PageInput};
use sea_orm::{ConnectionTrait, DbErr, PaginatorTrait, SelectorTrait};

/// A SeaORM query answered a page at a time.
pub trait Paged<'db, C: ConnectionTrait>: PaginatorTrait<'db, C> + Sized {
    /// The page `input` asks for, and the count across the whole query.
    #[allow(async_fn_in_trait)]
    async fn page(
        self,
        db: &'db C,
        input: &PageInput,
    ) -> Result<Page<<Self::Selector as SelectorTrait>::Item>, DbErr> {
        let pages = self.paginate(db, u64::from(input.size()));
        let total = pages.num_items().await?;
        let items = pages.fetch_page(u64::from(input.number() - 1)).await?;
        Ok(Page::new(items, input, total))
    }
}

impl<'db, C: ConnectionTrait, Q: PaginatorTrait<'db, C>> Paged<'db, C> for Q {}
