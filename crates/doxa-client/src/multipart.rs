//! `Multipart`: a form of text fields and files, for a route reading `axum::extract::Multipart`.

use crate::transport::Payload;

/// The fields of a multipart upload, in order.
///
/// ```
/// use doxa_client::Multipart;
///
/// let form = Multipart::new()
///     .text("title", "Q3")
///     .bytes("report", "q3.csv", "text/csv", b"a,b\n1,2\n".to_vec());
/// ```
#[derive(Debug, Clone, Default)]
pub struct Multipart {
    parts: Vec<Part>,
}

#[derive(Debug, Clone)]
struct Part {
    name: String,
    body: PartBody,
}

#[derive(Debug, Clone)]
enum PartBody {
    Text(String),
    File {
        filename: String,
        content_type: String,
        bytes: Vec<u8>,
    },
    #[cfg(target_arch = "wasm32")]
    Blob {
        filename: String,
        blob: web_sys::Blob,
    },
}

impl Multipart {
    /// An empty form.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a text field.
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(Part {
            name: name.into(),
            body: PartBody::Text(value.into()),
        });
        self
    }

    /// Add a file from bytes.
    pub fn bytes(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        self.parts.push(Part {
            name: name.into(),
            body: PartBody::File {
                filename: filename.into(),
                content_type: content_type.into(),
                bytes,
            },
        });
        self
    }

    /// Add a browser `Blob` or `File`, sent without copying it into wasm memory.
    #[cfg(target_arch = "wasm32")]
    pub fn blob(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        blob: &web_sys::Blob,
    ) -> Self {
        self.parts.push(Part {
            name: name.into(),
            body: PartBody::Blob {
                filename: filename.into(),
                blob: blob.clone(),
            },
        });
        self
    }

    /// The body, and the content type to send it with when the browser doesn't set one.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn encode(self) -> Result<(Option<String>, Payload), String> {
        use wasm_bindgen::JsValue;
        let err = |e: JsValue| format!("{e:?}");
        let form = web_sys::FormData::new().map_err(err)?;
        for part in self.parts {
            match part.body {
                PartBody::Text(v) => form.append_with_str(&part.name, &v).map_err(err)?,
                PartBody::File {
                    filename,
                    content_type,
                    bytes,
                } => {
                    let array = js_sys::Array::of1(&js_sys::Uint8Array::from(bytes.as_slice()));
                    let opts = web_sys::BlobPropertyBag::new();
                    opts.set_type(&content_type);
                    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&array, &opts)
                        .map_err(err)?;
                    form.append_with_blob_and_filename(&part.name, &blob, &filename)
                        .map_err(err)?;
                }
                PartBody::Blob { filename, blob } => form
                    .append_with_blob_and_filename(&part.name, &blob, &filename)
                    .map_err(err)?,
            }
        }
        Ok((None, Payload::Js(form.into())))
    }

    /// The body, and the content type naming its boundary.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn encode(self) -> Result<(Option<String>, Payload), String> {
        let boundary = self.boundary();
        let mut out = Vec::new();
        for part in &self.parts {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let name = quoted(&part.name);
            match &part.body {
                PartBody::Text(v) => {
                    out.extend_from_slice(
                        format!("content-disposition: form-data; name={name}\r\n\r\n").as_bytes(),
                    );
                    out.extend_from_slice(v.as_bytes());
                }
                PartBody::File {
                    filename,
                    content_type,
                    bytes,
                } => {
                    let filename = quoted(filename);
                    out.extend_from_slice(
                        format!(
                            "content-disposition: form-data; name={name}; filename={filename}\r\n\
                             content-type: {content_type}\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    out.extend_from_slice(bytes);
                }
            }
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        Ok((
            Some(format!("multipart/form-data; boundary={boundary}")),
            Payload::Bytes(out),
        ))
    }

    /// A boundary no part contains.
    #[cfg(not(target_arch = "wasm32"))]
    fn boundary(&self) -> String {
        let contents: Vec<&[u8]> = self
            .parts
            .iter()
            .map(|p| match &p.body {
                PartBody::Text(v) => v.as_bytes(),
                PartBody::File { bytes, .. } => bytes.as_slice(),
            })
            .collect();
        (0u64..)
            .map(|n| format!("doxa-boundary-{n:016x}"))
            .find(|b| {
                !contents
                    .iter()
                    .any(|c| c.windows(b.len()).any(|w| w == b.as_bytes()))
            })
            .expect("some boundary is free")
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
