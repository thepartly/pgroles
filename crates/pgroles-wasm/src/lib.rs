//! JavaScript boundary for browser-local policy authoring and plan analysis.
//!
//! Database inspection, credential resolution, and approval remain outside
//! the WebAssembly build. Authoring accepts unresolved password declarations;
//! explorer analysis requires password-free inputs.

use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate(input: JsValue) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let value = serde_wasm_bindgen::from_value(input).map_err(js_error)?;
    let request = serde_json::from_value(value).map_err(js_error)?;
    serialize_response(&pgroles_core::authoring::validate_policy(request))
}

#[wasm_bindgen]
pub fn compile(input: JsValue) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let value = serde_wasm_bindgen::from_value(input).map_err(js_error)?;
    let request = serde_json::from_value(value).map_err(js_error)?;
    serialize_response(&pgroles_core::authoring::compile_policy(request))
}

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
    serialize_response(&response)
}

fn serialize_response(response: &impl Serialize) -> Result<JsValue, JsValue> {
    response
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
