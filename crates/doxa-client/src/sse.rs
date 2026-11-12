//! Server-sent events, decoded into the route's event enum. Identical streams
//! share one connection: a [`Hub`] reads it, driven by whichever subscriber is
//! waiting, and copies each event to every subscriber.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;

use crate::fetch::Fetch;
use crate::service::Service;
use crate::transport::{Body, Request, Response};

/// How long to wait between reconnect attempts.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// First delay.
    pub initial: Duration,
    /// Longest delay.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
        }
    }
}

/// What [`EventStream::next_item`] yields.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamItem<E> {
    /// The connection is open: first on every stream, then after each reconnect.
    Connected,
    /// An event from the server.
    Event(E),
}

/// The events of an SSE route, in order.
///
/// ```ignore
/// let mut events = widget_events(&key).await?;
/// while let Some(event) = events.next().await? { /* … */ }
/// ```
pub struct EventStream<E> {
    hub: Rc<Hub>,
    inbox: Rc<Inbox>,
    _event: PhantomData<fn() -> E>,
}

impl<E: DeserializeOwned> EventStream<E> {
    pub(crate) fn subscribe(hub: Rc<Hub>) -> Self {
        let inbox = Rc::new(Inbox::default());
        inbox.items.borrow_mut().push_back(Item::Connected);
        hub.state
            .borrow_mut()
            .subscribers
            .push(Rc::downgrade(&inbox));
        Self {
            hub,
            inbox,
            _event: PhantomData,
        }
    }

    /// Reopen the stream when it drops, resuming from the last event id.
    pub fn reconnect(self, backoff: Backoff) -> Self {
        self.hub
            .state
            .borrow_mut()
            .backoff
            .get_or_insert((backoff, backoff.initial));
        self
    }

    /// The next event; `Ok(None)` once the server closes the stream.
    pub async fn next(&mut self) -> Result<Option<E>, Fetch> {
        loop {
            match self.next_item().await? {
                Some(StreamItem::Event(event)) => return Ok(Some(event)),
                Some(StreamItem::Connected) => continue,
                None => return Ok(None),
            }
        }
    }

    /// [`next`](Self::next), also reporting each connection; refetch on `Connected` when the
    /// route has no replay, since events sent during a gap are lost.
    pub async fn next_item(&mut self) -> Result<Option<StreamItem<E>>, Fetch> {
        loop {
            let item = std::future::poll_fn(|cx| self.poll_item(cx)).await;
            match item {
                None => return Ok(None),
                Some(Item::Connected) => return Ok(Some(StreamItem::Connected)),
                Some(Item::Failed(e)) => return Err(e),
                Some(Item::Frame(frame)) => match frame.event.as_deref() {
                    Some("error") => return Err(Fetch::Stream(frame.data.clone())),
                    _ if frame.data.is_empty() => continue,
                    _ => {
                        return serde_json::from_str(&frame.data)
                            .map(|event| Some(StreamItem::Event(event)))
                            .map_err(|e| Fetch::Decode(e.to_string()))
                    }
                },
            }
        }
    }

    fn poll_item(&self, cx: &mut Context<'_>) -> Poll<Option<Item>> {
        loop {
            if let Some(item) = self.inbox.items.borrow_mut().pop_front() {
                return Poll::Ready(Some(item));
            }
            self.hub.waiting.register(cx.waker());
            match self.hub.pump() {
                Poll::Ready(true) => continue,
                Poll::Ready(false) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The events a mutating route answers with. Sent once and never reopened, since
/// reopening would repeat the mutation; dropping it aborts the request.
///
/// ```compile_fail
/// fn resume(s: doxa_client::Once<()>) { s.reconnect(Default::default()); }
/// ```
/// ```
/// fn resume(s: doxa_client::EventStream<()>) { s.reconnect(Default::default()); }
/// ```
pub struct Once<E>(EventStream<E>);

impl<E: DeserializeOwned> Once<E> {
    pub(crate) fn subscribe(hub: Rc<Hub>) -> Self {
        Self(EventStream::subscribe(hub))
    }

    /// The next event; `Ok(None)` once the server closes the stream.
    pub async fn next(&mut self) -> Result<Option<E>, Fetch> {
        self.0.next().await
    }
}

#[derive(Default)]
struct Inbox {
    items: RefCell<VecDeque<Item>>,
}

#[derive(Clone)]
enum Item {
    Connected,
    Frame(Rc<Frame>),
    Failed(Fetch),
}

/// Wakes every subscriber waiting on the connection, whichever one polled it last.
#[derive(Default)]
struct Waiting(Mutex<Vec<Waker>>);

impl Waiting {
    fn register(&self, waker: &Waker) {
        let mut wakers = self.0.lock().unwrap();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }
}

impl Wake for Waiting {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let wakers = std::mem::take(&mut *self.0.lock().unwrap());
        wakers.into_iter().for_each(Waker::wake);
    }
}

/// One open event stream, shared by every subscriber to the same route and arguments.
#[doc(hidden)]
pub struct Hub {
    /// The request as the call built it; each reconnect sends it through the layers afresh.
    request: Request,
    client: Rc<Service>,
    waiting: Arc<Waiting>,
    state: RefCell<HubState>,
}

/// A reconnect's answer, with the session it was sent in.
type Reopened = (u64, Result<Response, Fetch>);

struct HubState {
    body: Option<Body>,
    reopening: Option<LocalBoxFuture<'static, Reopened>>,
    buffer: Vec<u8>,
    scanned: usize,
    last_id: Option<String>,
    backoff: Option<(Backoff, Duration)>,
    done: bool,
    subscribers: Vec<Weak<Inbox>>,
}

impl Hub {
    pub(crate) fn new(request: Request, client: Rc<Service>, body: Body) -> Self {
        Self {
            request,
            client,
            waiting: Arc::default(),
            state: RefCell::new(HubState {
                body: Some(body),
                reopening: None,
                buffer: Vec::new(),
                scanned: 0,
                last_id: None,
                backoff: None,
                done: false,
                subscribers: Vec::new(),
            }),
        }
    }

    /// Whether a new subscriber would still get events.
    pub(crate) fn is_open(&self) -> bool {
        !self.state.borrow().done
    }

    /// Drop the connection, ending every subscriber's stream with an error.
    pub(crate) fn close(&self) {
        let mut s = self.state.borrow_mut();
        if s.done {
            return;
        }
        s.body = None;
        s.reopening = None;
        s.done = true;
        broadcast(
            &mut s,
            Item::Failed(Fetch::Stream("the session changed".into())),
        );
        drop(s);
        self.waiting.wake_by_ref();
    }

    /// Read what the connection has. `Ready(true)`: progress, look again;
    /// `Ready(false)`: the stream is over.
    fn pump(&self) -> Poll<bool> {
        let waker = Waker::from(self.waiting.clone());
        let mut cx = Context::from_waker(&waker);
        let mut s = self.state.borrow_mut();
        if s.done {
            return Poll::Ready(false);
        }
        if let Some(mut reopening) = s.reopening.take() {
            // Polled unborrowed: sending can end the session, which closes this hub.
            drop(s);
            let Poll::Ready((session, result)) = reopening.as_mut().poll(&mut cx) else {
                let mut s = self.state.borrow_mut();
                if !s.done {
                    s.reopening = Some(reopening);
                }
                return Poll::Pending;
            };
            let current = match &result {
                Ok(resp) => self.client.observe_session(resp, session),
                Err(_) => self.client.session() == session,
            };
            let mut s = self.state.borrow_mut();
            if !current {
                s.done = true;
            }
            if s.done {
                return Poll::Ready(true);
            }
            match result {
                Ok(resp) if resp.status < 400 => {
                    s.body = Some(resp.body);
                    s.buffer.clear();
                    s.scanned = 0;
                    if let Some((policy, delay)) = s.backoff.as_mut() {
                        *delay = policy.initial;
                    }
                    broadcast(&mut s, Item::Connected);
                    drop(s);
                    self.waiting.wake_by_ref();
                    return Poll::Ready(true);
                }
                Ok(Response {
                    status: status @ (401 | 403 | 404),
                    body: Body::Full(body),
                    ..
                }) => {
                    broadcast(&mut s, Item::Failed(Fetch::from_status(status, &body)));
                    s.done = true;
                }
                _ => {}
            }
            return Poll::Ready(true);
        }
        let chunk = match s.body.as_mut() {
            Some(Body::Stream(stream)) => match stream.poll_next_unpin(&mut cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(chunk) => chunk,
            },
            Some(Body::Full(_)) => match s.body.take() {
                Some(Body::Full(bytes)) => Some(Ok(bytes)),
                _ => None,
            },
            None => None,
        };
        match chunk {
            Some(Ok(bytes)) => {
                s.buffer.extend_from_slice(&bytes);
                let HubState {
                    buffer, scanned, ..
                } = &mut *s;
                let mut frames = Vec::new();
                while let Some(frame) = take_frame(buffer, scanned) {
                    frames.push(frame);
                }
                for frame in frames {
                    if let Some(id) = &frame.id {
                        s.last_id = Some(id.clone());
                    }
                    broadcast(&mut s, Item::Frame(Rc::new(frame)));
                }
                if s.buffer.len() > MAX_FRAME {
                    let error = format!("an event ran past {MAX_FRAME} bytes");
                    broadcast(&mut s, Item::Failed(Fetch::Stream(error)));
                    s.body = None;
                    s.done = true;
                }
            }
            Some(Err(e)) if s.backoff.is_none() => {
                broadcast(&mut s, Item::Failed(Fetch::Network(e)));
                s.done = true;
            }
            None if s.backoff.is_none() => s.done = true,
            _ => {
                s.body = None;
                let reopen = self.reopen(&mut s);
                s.reopening = Some(reopen);
            }
        }
        drop(s);
        self.waiting.wake_by_ref();
        Poll::Ready(true)
    }

    fn reopen(&self, s: &mut HubState) -> LocalBoxFuture<'static, Reopened> {
        let (policy, delay) = s.backoff.expect("reopened only with a backoff");
        s.backoff = Some((policy, (delay * 2).min(policy.max)));
        let mut request = self.request.clone();
        if let Some(id) = &s.last_id {
            request.headers.push(("last-event-id".into(), id.clone()));
        }
        let client = self.client.clone();
        Box::pin(async move {
            crate::clock::sleep(delay).await;
            let session = client.session();
            let mut result = client.send(request).await;
            if let Ok(resp) = &mut result {
                if resp.status >= 400 {
                    let body = std::mem::replace(&mut resp.body, Body::Full(Vec::new()));
                    resp.body = Body::Full(body.bytes().await.unwrap_or_default());
                }
            }
            (session, result)
        })
    }
}

fn broadcast(s: &mut HubState, item: Item) {
    s.subscribers.retain(|w| match w.upgrade() {
        Some(inbox) => {
            inbox.items.borrow_mut().push_back(item.clone());
            true
        }
        None => false,
    });
}

/// The longest event the stream buffers before giving up on it.
const MAX_FRAME: usize = 1 << 20;

/// The next whole frame; `scanned` is how far `buffer` is known to hold no boundary.
fn take_frame(buffer: &mut Vec<u8>, scanned: &mut usize) -> Option<Frame> {
    // A boundary is up to 4 bytes, so one may straddle the last scan's end.
    let Some((end, skip)) = find_boundary(buffer, scanned.saturating_sub(3)) else {
        *scanned = buffer.len();
        return None;
    };
    *scanned = 0;
    let raw: Vec<u8> = buffer.drain(..end + skip).take(end).collect();
    Some(Frame::parse(&String::from_utf8_lossy(&raw)))
}

fn find_boundary(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    (from..buf.len()).find_map(|i| {
        if buf[i..].starts_with(b"\r\n\r\n") {
            Some((i, 4))
        } else if buf[i..].starts_with(b"\n\n") {
            Some((i, 2))
        } else {
            None
        }
    })
}

#[derive(Debug, Default, PartialEq)]
struct Frame {
    event: Option<String>,
    data: String,
    id: Option<String>,
}

impl Frame {
    fn parse(raw: &str) -> Frame {
        let mut frame = Frame::default();
        let mut data = Vec::new();
        for line in raw.lines() {
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line, ""),
            };
            match field {
                "event" => frame.event = Some(value.to_owned()),
                "data" => data.push(value),
                "id" => frame.id = Some(value.to_owned()),
                _ => {}
            }
        }
        frame.data = data.join("\n");
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[derive(Debug, PartialEq, serde::Deserialize)]
    #[serde(tag = "event", content = "data", rename_all = "snake_case")]
    enum Ev {
        Renamed { name: String },
        Deleted,
    }

    fn request() -> Request {
        Request {
            method: doxa_wire::Method::Get,
            url: "/e".into(),
            headers: vec![],
            body: None,
            credentials: false,
        }
    }

    fn hub(raw: &str, transport: MockTransport) -> Rc<Hub> {
        let service = crate::service("");
        service.layers().push(crate::layer::transport(transport));
        Rc::new(Hub::new(
            request(),
            service,
            Body::Full(raw.as_bytes().to_vec()),
        ))
    }

    fn stream(raw: &str) -> EventStream<Ev> {
        EventStream::subscribe(hub(raw, MockTransport::new()))
    }

    #[test]
    fn a_boundary_split_across_chunks_is_found_without_rescanning() {
        let (mut buffer, mut scanned) = (b"data: a\r\n".to_vec(), 0);
        assert!(take_frame(&mut buffer, &mut scanned).is_none());
        assert_eq!(scanned, buffer.len());
        buffer.extend_from_slice(b"\r\ndata: b");
        let frame = take_frame(&mut buffer, &mut scanned).unwrap();
        assert_eq!(frame.data, "a");
        assert_eq!((buffer.as_slice(), scanned), (&b"data: b"[..], 0));
    }

    #[test]
    fn an_event_that_never_ends_fails_the_stream() {
        let raw = format!("data: {}", "x".repeat(MAX_FRAME + 1));
        let mut s = stream(&raw);
        crate::task::block_on(async {
            assert!(matches!(s.next().await, Err(Fetch::Stream(_))));
        });
    }

    #[test]
    fn events_decode_from_the_whole_tagged_payload() {
        let raw = "event: renamed\ndata: {\"event\":\"renamed\",\"data\":{\"name\":\"a\"}}\n\n: keepalive\n\nevent: deleted\ndata: {\"event\":\"deleted\"}\n\n";
        let mut s = stream(raw);
        crate::task::block_on(async {
            assert_eq!(
                s.next().await.unwrap(),
                Some(Ev::Renamed { name: "a".into() })
            );
            assert_eq!(s.next().await.unwrap(), Some(Ev::Deleted));
            assert_eq!(s.next().await.unwrap(), None);
        });
    }

    #[test]
    fn an_error_event_is_an_error() {
        let mut s = stream("event: error\ndata: upstream gone\n\n");
        let err = crate::task::block_on(s.next()).unwrap_err();
        assert!(matches!(err, Fetch::Stream(m) if m == "upstream gone"));
    }

    #[test]
    fn every_subscriber_gets_every_event() {
        let h = hub("data: {\"event\":\"deleted\"}\n\n", MockTransport::new());
        let mut a = EventStream::<Ev>::subscribe(h.clone());
        let mut b = EventStream::<Ev>::subscribe(h);
        crate::task::block_on(async {
            assert_eq!(a.next().await.unwrap(), Some(Ev::Deleted));
            assert_eq!(b.next().await.unwrap(), Some(Ev::Deleted));
            assert_eq!(a.next().await.unwrap(), None);
            assert_eq!(b.next().await.unwrap(), None);
        });
    }

    #[test]
    fn a_dropped_stream_reconnects_from_the_last_event_id() {
        let mock = MockTransport::new();
        mock.respond(200, vec![], b"data: {\"event\":\"deleted\"}\n\n".to_vec());
        let h = hub("id: 7\ndata: {\"event\":\"deleted\"}\n\n", mock.clone());
        let mut s = EventStream::<Ev>::subscribe(h).reconnect(Backoff {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(1),
        });
        crate::task::block_on(async {
            assert_eq!(s.next().await.unwrap(), Some(Ev::Deleted));
            assert_eq!(s.next().await.unwrap(), Some(Ev::Deleted));
        });
        let sent = mock.requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].header("last-event-id"), Some("7"));
    }

    fn fast() -> Backoff {
        Backoff {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(1),
        }
    }

    #[test]
    fn an_item_stream_reports_each_connection_before_its_events() {
        let mock = MockTransport::new();
        mock.respond(200, vec![], b"data: {\"event\":\"deleted\"}\n\n".to_vec());
        let h = hub("data: {\"event\":\"deleted\"}\n\n", mock);
        let mut s = EventStream::<Ev>::subscribe(h).reconnect(fast());
        crate::task::block_on(async {
            for expected in [
                StreamItem::Connected,
                StreamItem::Event(Ev::Deleted),
                StreamItem::Connected,
                StreamItem::Event(Ev::Deleted),
            ] {
                assert_eq!(s.next_item().await.unwrap(), Some(expected));
            }
        });
    }

    #[test]
    fn every_subscriber_hears_of_a_reconnect() {
        let mock = MockTransport::new();
        mock.respond(200, vec![], b"data: {\"event\":\"deleted\"}\n\n".to_vec());
        let h = hub("", mock);
        let mut a = EventStream::<Ev>::subscribe(h.clone()).reconnect(fast());
        let mut b = EventStream::<Ev>::subscribe(h);
        crate::task::block_on(async {
            for s in [&mut a, &mut b] {
                assert_eq!(s.next_item().await.unwrap(), Some(StreamItem::Connected));
                assert_eq!(s.next_item().await.unwrap(), Some(StreamItem::Connected));
                assert_eq!(
                    s.next_item().await.unwrap(),
                    Some(StreamItem::Event(Ev::Deleted))
                );
            }
        });
    }

    #[test]
    fn a_failed_reopen_reports_no_connection() {
        let mock = MockTransport::new();
        mock.respond(503, vec![], Vec::new());
        mock.respond(200, vec![], b"data: {\"event\":\"deleted\"}\n\n".to_vec());
        let h = hub("", mock);
        let mut s = EventStream::<Ev>::subscribe(h).reconnect(fast());
        crate::task::block_on(async {
            assert_eq!(s.next_item().await.unwrap(), Some(StreamItem::Connected));
            assert_eq!(s.next_item().await.unwrap(), Some(StreamItem::Connected));
            assert_eq!(
                s.next_item().await.unwrap(),
                Some(StreamItem::Event(Ev::Deleted))
            );
        });
    }
}
