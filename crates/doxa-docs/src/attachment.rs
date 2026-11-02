//! `Attachment`: a file a route sends to be saved, which the client receives as a `Download`.

use axum::body::Bytes;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use utoipa::openapi::path::Operation;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, Type};
use utoipa::openapi::{Content, RefOr, Schema};

use crate::DocResponseBody;

/// A file response: bytes, a content type, and the name a browser saves it under.
///
/// ```
/// use doxa_docs::Attachment;
///
/// let pdf = Attachment::new(b"%PDF-1.7".to_vec())
///     .content_type("application/pdf")
///     .filename("Q3 report.pdf");
/// ```
#[derive(Debug, Clone)]
pub struct Attachment {
    bytes: Bytes,
    content_type: String,
    filename: Option<String>,
}

impl Attachment {
    /// `bytes`, as `application/octet-stream` until [`content_type`](Self::content_type).
    pub fn new(bytes: impl Into<Bytes>) -> Attachment {
        Attachment {
            bytes: bytes.into(),
            content_type: "application/octet-stream".into(),
            filename: None,
        }
    }

    /// The file's media type.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Attachment {
        self.content_type = content_type.into();
        self
    }

    /// The name to save it under.
    pub fn filename(mut self, filename: impl Into<String>) -> Attachment {
        self.filename = Some(filename.into());
        self
    }
}

impl IntoResponse for Attachment {
    fn into_response(self) -> Response {
        let mut res = self.bytes.into_response();
        let h = res.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&self.content_type) {
            h.insert(header::CONTENT_TYPE, v);
        }
        let disposition = match &self.filename {
            Some(name) => format!(
                "attachment; filename=\"{}\"; filename*=UTF-8''{}",
                ascii_fallback(name),
                percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
            ),
            None => "attachment".into(),
        };
        if let Ok(v) = HeaderValue::from_str(&disposition) {
            h.insert(header::CONTENT_DISPOSITION, v);
        }
        res
    }
}

/// `name` with anything a quoted header parameter can't carry replaced by `_`.
fn ascii_fallback(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            ' '..='~' if c != '"' && c != '\\' => c,
            _ => '_',
        })
        .collect()
}

impl DocResponseBody for Attachment {
    fn describe(op: &mut Operation, _: &mut Vec<(String, RefOr<Schema>)>) {
        if op.responses.responses.contains_key("200") {
            return;
        }
        let binary = ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
            .build();
        let response = ResponseBuilder::new()
            .description("A file to save.")
            .content(
                "application/octet-stream",
                Content::new(Some(RefOr::T(Schema::Object(binary)))),
            )
            .build();
        op.responses
            .responses
            .insert("200".to_string(), RefOr::T(response));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filename_survives_in_both_forms() {
        let res = Attachment::new("x")
            .content_type("text/csv")
            .filename("Q3 \"ü\".csv")
            .into_response();
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/csv");
        assert_eq!(
            res.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"Q3 ___.csv\"; filename*=UTF-8''Q3%20%22%C3%BC%22%2Ecsv"
        );
    }
}
