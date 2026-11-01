//! Server-sent events, decoded into the route's event enum.

use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Duration;

use futures_util::StreamExt;
use serde::de::DeserializeOwned;

use crate::fetch::Fetch;
use crate::transport::{Body, Request, Transport};

/// Where a stream came from, so it can be reopened.
#[doc(hidden)]
#[derive(Clone)]
pub struct Source {
    pub(crate) request: Request,
    pub(crate) transport: Rc<dyn Transport>,
}

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

/// The events of an SSE route, in order.
///
/// ```ignore
/// let mut events = widget_events(&key).await?;
/// while let Some(event) = events.next().await? { /* … */ }
/// ```
pub struct EventStream<E> {
    body: Option<Body>,
    buffer: Vec<u8>,
    last_id: Option<String>,
    source: Source,
    backoff: Option<(Backoff, Duration)>,
    _event: PhantomData<fn() -> E>,
}

impl<E: DeserializeOwned> EventStream<E> {
    pub(crate) fn new(body: Body, source: Source) -> Self {
        Self {
            body: Some(body),
            buffer: Vec::new(),
            last_id: None,
            source,
            backoff: None,
            _event: PhantomData,
        }
    }

    /// Reopen the stream when it drops, resuming from the last event id.
    pub fn reconnect(mut self, backoff: Backoff) -> Self {
        self.backoff = Some((backoff, backoff.initial));
        self
    }

    /// The next event; `Ok(None)` once the server closes the stream.
    pub async fn next(&mut self) -> Result<Option<E>, Fetch> {
        loop {
            if let Some(frame) = self.take_frame() {
                if let Some(id) = frame.id {
                    self.last_id = Some(id);
                }
                match frame.event.as_deref() {
                    Some("error") => return Err(Fetch::Stream(frame.data)),
                    _ if frame.data.is_empty() => continue,
                    _ => {
                        return serde_json::from_str(&frame.data)
                            .map(Some)
                            .map_err(|e| Fetch::Decode(e.to_string()))
                    }
                }
            }
            let chunk = match self.body.as_mut() {
                Some(Body::Stream(s)) => s.next().await,
                Some(Body::Full(_)) => match self.body.take() {
                    Some(Body::Full(b)) => Some(Ok(b)),
                    _ => None,
                },
                None => None,
            };
            match chunk {
                Some(Ok(bytes)) => self.buffer.extend_from_slice(&bytes),
                Some(Err(e)) if self.backoff.is_none() => return Err(Fetch::Network(e)),
                None if self.backoff.is_none() => return Ok(None),
                _ => self.reopen().await?,
            }
        }
    }

    async fn reopen(&mut self) -> Result<(), Fetch> {
        let Some((policy, delay)) = self.backoff else {
            return Ok(());
        };
        futures_timer::Delay::new(delay).await;
        self.backoff = Some((policy, (delay * 2).min(policy.max)));
        let mut request = self.source.request.clone();
        if let Some(id) = &self.last_id {
            request.headers.push(("last-event-id".into(), id.clone()));
        }
        match self.source.transport.send(request).await {
            Ok(resp) if resp.status < 400 => {
                self.body = Some(resp.body);
                self.buffer.clear();
                self.backoff = Some((policy, policy.initial));
            }
            _ => self.body = None,
        }
        Ok(())
    }

    fn take_frame(&mut self) -> Option<Frame> {
        let (end, skip) = find_boundary(&self.buffer)?;
        let raw: Vec<u8> = self.buffer.drain(..end + skip).take(end).collect();
        Some(Frame::parse(&String::from_utf8_lossy(&raw)))
    }
}

fn find_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    (0..buf.len()).find_map(|i| {
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

    fn stream(raw: &str) -> EventStream<Ev> {
        let source = Source {
            request: Request {
                method: doxa_wire::Method::Get,
                url: "/e".into(),
                headers: vec![],
                body: None,
                credentials: false,
            },
            transport: Rc::new(MockTransport::new()),
        };
        EventStream::new(Body::Full(raw.as_bytes().to_vec()), source)
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
}
