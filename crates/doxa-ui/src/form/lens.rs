//! Where each field of a form lives in its value, and the keys of its list rows.

use std::any::Any;
use std::rc::Rc;

/// A list row's key: made by the list, never reused, so a row keeps its DOM through a reorder.
pub type RowKey = u64;

/// The row keys of every list in a form, by the list's lens.
#[derive(Default)]
pub(crate) struct Rows {
    next: RowKey,
    lists: Vec<(u32, Vec<RowKey>)>,
}

impl Rows {
    pub(crate) fn keys(&self, list: u32) -> &[RowKey] {
        self.lists
            .iter()
            .find(|(l, _)| *l == list)
            .map_or(&[], |(_, k)| k.as_slice())
    }

    pub(crate) fn index(&self, list: u32, key: RowKey) -> Option<usize> {
        self.keys(list).iter().position(|k| *k == key)
    }

    pub(crate) fn keys_mut(&mut self, list: u32) -> &mut Vec<RowKey> {
        let at = match self.lists.iter().position(|(l, _)| *l == list) {
            Some(at) => at,
            None => {
                self.lists.push((list, Vec::new()));
                self.lists.len() - 1
            }
        };
        &mut self.lists[at].1
    }

    pub(crate) fn fresh(&mut self) -> RowKey {
        self.next += 1;
        self.next
    }

    /// Give `list` one key per row: new rows at the end get fresh keys, gone ones lose theirs.
    pub(crate) fn sync(&mut self, list: u32, len: usize) {
        let have = self.keys(list).len();
        if have > len {
            self.keys_mut(list).truncate(len);
        }
        for _ in have..len {
            let key = self.fresh();
            self.keys_mut(list).push(key);
        }
    }
}

type Get<R, V> = Rc<dyn for<'a> Fn(&'a R, &Rows) -> Option<&'a V>>;
type GetMut<R, V> = Rc<dyn for<'a> Fn(&'a mut R, &Rows) -> Option<&'a mut V>>;
type Put<R, V> = Rc<dyn Fn(&mut R, &Rows, V)>;

fn getter<R, V>(f: impl for<'a> Fn(&'a R, &Rows) -> Option<&'a V> + 'static) -> Get<R, V> {
    Rc::new(f)
}

fn setter<R, V>(
    f: impl for<'a> Fn(&'a mut R, &Rows) -> Option<&'a mut V> + 'static,
) -> GetMut<R, V> {
    Rc::new(f)
}

/// The way from a form's value `R` to one `V` inside it; `None` once its row is removed.
pub(crate) type Path = Rc<dyn Fn(&Rows) -> Option<String>>;

pub(crate) struct Lens<R, V> {
    pub(crate) path: Path,
    pub(crate) get: Get<R, V>,
    pub(crate) get_mut: GetMut<R, V>,
    pub(crate) put: Put<R, V>,
}

impl<R: 'static, V: 'static> Lens<R, V> {
    fn new(path: Path, get: Get<R, V>, get_mut: GetMut<R, V>) -> Self {
        let m = get_mut.clone();
        let put = Rc::new(move |r: &mut R, rows: &Rows, v| {
            if let Some(at) = m(r, rows) {
                *at = v;
            }
        });
        Lens {
            path,
            get,
            get_mut,
            put,
        }
    }
}

impl<R: 'static> Lens<R, R> {
    pub(crate) fn root() -> Self {
        Lens::new(
            Rc::new(|_| Some(String::new())),
            getter(|r, _| Some(r)),
            setter(|r, _| Some(r)),
        )
    }
}

impl<R: 'static, S: 'static> Lens<R, S> {
    /// The part `seg` of what this lens reaches, while `get` finds it there.
    pub(crate) fn part<V: 'static>(
        self: &Rc<Self>,
        seg: String,
        get: impl for<'a> Fn(&'a S) -> Option<&'a V> + 'static,
        get_mut: impl for<'a> Fn(&'a mut S) -> Option<&'a mut V> + 'static,
    ) -> Lens<R, V> {
        let (p, g, m) = (self.path.clone(), self.get.clone(), self.get_mut.clone());
        Lens::new(
            Rc::new(move |rows| p(rows).map(|p| join(&p, &seg))),
            getter(move |r, rows| g(r, rows).and_then(&get)),
            setter(move |r, rows| m(r, rows).and_then(&get_mut)),
        )
    }

    /// Which variant of the enum this lens reaches, named as `get` names it and changed by `set`.
    pub(crate) fn variant(
        self: &Rc<Self>,
        get: fn(&S) -> &'static String,
        set: fn(&mut S, String),
    ) -> Lens<R, String> {
        let (g, m) = (self.get.clone(), self.get_mut.clone());
        Lens {
            path: self.path.clone(),
            get: getter(move |r, rows| g(r, rows).map(get)),
            get_mut: setter(|_, _| None),
            put: Rc::new(move |r, rows, v| {
                if let Some(s) = m(r, rows) {
                    set(s, v);
                }
            }),
        }
    }
}

impl<R: 'static, E: 'static> Lens<R, Vec<E>> {
    /// The row keyed `key` of the list this lens reaches, which is lens `list`.
    pub(crate) fn row(self: &Rc<Self>, list: u32, key: RowKey) -> Lens<R, E> {
        let (p, g, m) = (self.path.clone(), self.get.clone(), self.get_mut.clone());
        Lens::new(
            Rc::new(move |rows| Some(format!("{}[{}]", p(rows)?, rows.index(list, key)?))),
            getter(move |r, rows| g(r, rows)?.get(rows.index(list, key)?)),
            setter(move |r, rows| {
                let i = rows.index(list, key)?;
                m(r, rows)?.get_mut(i)
            }),
        )
    }
}

fn join(prefix: &str, seg: &str) -> String {
    match prefix {
        _ if seg.starts_with('[') => format!("{prefix}{seg}"),
        "" => seg.to_owned(),
        p => format!("{p}.{seg}"),
    }
}

/// Every lens a form has handed out, found again by where it points.
#[derive(Default)]
pub(crate) struct Lenses(Vec<Interned>);

struct Interned {
    key: String,
    path: Path,
    lens: Rc<dyn Any>,
}

impl Lenses {
    /// The id of the lens at `key`, made by `make` the first time.
    pub(crate) fn intern<R: 'static, V: 'static>(
        &mut self,
        key: String,
        make: impl FnOnce() -> Lens<R, V>,
    ) -> u32 {
        if let Some(at) = self.0.iter().position(|i| i.key == key) {
            return at as u32;
        }
        let lens = make();
        self.0.push(Interned {
            key,
            path: lens.path.clone(),
            lens: Rc::new(lens),
        });
        (self.0.len() - 1) as u32
    }

    pub(crate) fn key(&self, id: u32) -> &str {
        &self.0[id as usize].key
    }

    pub(crate) fn path(&self, id: u32) -> Path {
        self.0[id as usize].path.clone()
    }

    pub(crate) fn get<R: 'static, V: 'static>(&self, id: u32) -> Rc<Lens<R, V>> {
        self.0[id as usize]
            .lens
            .clone()
            .downcast()
            .unwrap_or_else(|_| unreachable!("a lens id names one type"))
    }
}
