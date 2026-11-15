//! Every mounted route runs under a `route` span its macro declared, and a handler's own
//! `#[instrument]` nests inside it.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

#[derive(Clone, doxa::State)]
struct AppState;

#[doxa::service]
pub struct Widgets;

#[doxa::get("/widgets/{id}")]
async fn get_widget(axum::extract::Path(id): axum::extract::Path<u32>) -> String {
    inner(id).await
}

#[tracing::instrument]
async fn inner(id: u32) -> String {
    let parent = tracing::Span::current()
        .metadata()
        .map(|m| m.name())
        .unwrap_or_default();
    format!("{id} under {parent}")
}

#[doxa::get("/quiet", trace = false)]
async fn quiet() -> String {
    tracing::Span::current()
        .metadata()
        .map(|m| m.name().to_owned())
        .unwrap_or_else(|| "none".to_owned())
}

/// Every field each `route` span was opened or recorded with.
#[derive(Clone, Default)]
struct Spans(Arc<Mutex<Vec<(String, String)>>>);

struct Fields<'a>(&'a mut Vec<(String, String)>);

impl Visit for Fields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Spans {
    fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
        if attrs.metadata().name() == "route" {
            attrs.record(&mut Fields(&mut self.0.lock().unwrap()));
        }
    }
    fn on_record(&self, id: &Id, values: &Record<'_>, cx: Context<'_, S>) {
        if cx.span(id).is_some_and(|s| s.name() == "route") {
            values.record(&mut Fields(&mut self.0.lock().unwrap()));
        }
    }
}

async fn get(uri: &str, tenant: Option<&str>) -> String {
    let (router, _) = doxa::app(&AppState).split_for_parts();
    let mut request = Request::get(uri).body(Body::empty()).unwrap();
    if let Some(tenant) = tenant {
        request
            .extensions_mut()
            .insert(doxa::__private::SpanTenant(tenant.to_owned()));
    }
    let response = router.oneshot(request).await.unwrap();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn a_route_s_span_names_it_its_tenant_and_its_parameters() {
    let spans = Spans::default();
    let subscriber = tracing_subscriber::registry().with(spans.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let body = get("/widgets/42", Some("acme")).await;

    assert_eq!(
        body, "42 under inner",
        "the handler's own span is the innermost"
    );
    let fields = spans.0.lock().unwrap().clone();
    for (name, value) in [
        ("handler", "get_widget"),
        ("route", "GET /widgets/{id}"),
        ("tenant", "acme"),
        ("id", "42"),
    ] {
        assert!(
            fields.iter().any(|(n, v)| n == name && v == value),
            "{name}={value} missing from {fields:?}",
        );
    }
}

#[tokio::test]
async fn trace_false_opens_no_span() {
    let spans = Spans::default();
    let subscriber = tracing_subscriber::registry().with(spans.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    assert_eq!(get("/quiet", None).await, "none");
    assert!(spans.0.lock().unwrap().is_empty());
}
