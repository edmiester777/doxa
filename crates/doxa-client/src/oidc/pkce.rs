//! Authorization code with PKCE (S256): the verifier, its challenge, and the URL encoding.

use sha2::{Digest, Sha256};

use super::host::Host;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Base64url, padded or not; `None` if it isn't.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// 32 random bytes, base64url: a verifier, `state` or `nonce`.
pub(crate) fn random(host: &dyn Host) -> String {
    let mut bytes = [0u8; 32];
    host.random(&mut bytes);
    encode(&bytes)
}

/// The S256 challenge for `verifier`.
pub(crate) fn challenge(verifier: &str) -> String {
    encode(&Sha256::digest(verifier.as_bytes()))
}

/// `pairs` as a query string or form body.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    serde_urlencoded::to_string(pairs).unwrap_or_default()
}

/// The query of `url` as pairs.
pub(crate) fn query(url: &str) -> Vec<(String, String)> {
    let Some((_, q)) = url.split_once('?') else {
        return Vec::new();
    };
    let q = q.split('#').next().unwrap_or(q);
    serde_urlencoded::from_str(q).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_and_matches_the_rfc_challenge() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(decode(&encode(bytes)).unwrap(), bytes);
        }
        // RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
