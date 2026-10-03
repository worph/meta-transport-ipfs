//! The bitswap byte path, plus the few helpers it shared with meta-share's
//! other byte tiers.

pub mod bitswap;

use std::time::Duration;

use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;

use crate::api::range::{parse_range_header, RangeOutcome};

/// Marks a request from meta-watch's byte proxy for a demuxer source.
pub const PLAYER_HEADER: &str = "x-metamesh-player";

/// Single bitswap block fetch budget (`META_SHARE_BITSWAP_RAW_TIMEOUT_SECS`).
const BITSWAP_RAW_TIMEOUT: Duration = Duration::from_secs(30);

pub fn raw_timeout() -> Duration {
    std::env::var("META_SHARE_BITSWAP_RAW_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(BITSWAP_RAW_TIMEOUT)
}

/// An in-memory block as a range response: `206` slice, `416`, or `200`.
pub fn bytes_to_response(bytes: Vec<u8>, inbound_range: Option<&HeaderValue>) -> Response {
    use axum::body::Body;
    use axum::http::{header, HeaderMap};
    use axum::response::IntoResponse;
    let total = bytes.len() as u64;
    match parse_range_header(inbound_range, total) {
        RangeOutcome::Ok { start, end } => {
            let s = start as usize;
            let e = end as usize;
            let body = bytes[s..=e].to_vec();
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len() as u64));
            headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            let cr = format!("bytes {start}-{end}/{total}");
            headers.insert(header::CONTENT_RANGE, HeaderValue::from_str(&cr).expect("ascii content-range"));
            (StatusCode::PARTIAL_CONTENT, headers, Body::from(body)).into_response()
        }
        RangeOutcome::Unsatisfiable => {
            let mut headers = HeaderMap::new();
            let cr = format!("bytes */{total}");
            headers.insert(header::CONTENT_RANGE, HeaderValue::from_str(&cr).expect("ascii content-range"));
            (StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response()
        }
        RangeOutcome::Absent | RangeOutcome::Unsupported => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
            headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            (StatusCode::OK, headers, Body::from(bytes)).into_response()
        }
    }
}
