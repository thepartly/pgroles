//! JavaScript boundary for browser-local pgroles explorer analysis.
//!
//! This crate accepts only the versioned, sanitized explorer request defined
//! by `pgroles-core`. Database inspection, credentials, and password handling
//! intentionally remain outside the WebAssembly build.

use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Analyze a desired manifest against a sanitized current-state snapshot.
///
/// `input` must conform to `pgroles.explorer.v1`. The result is serialized as
/// JSON-compatible JavaScript values so maps and enums have predictable
/// representations in browser code.
#[wasm_bindgen]
pub fn analyze(input: JsValue) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let value = serde_wasm_bindgen::from_value(input).map_err(js_error)?;
    let request = serde_json::from_value(value).map_err(js_error)?;
    let response = pgroles_core::explorer::analyze(request).map_err(js_error)?;

    response
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
