use std::path::PathBuf;

use pgroles_core::authoring::{PolicyRequest, compile_policy, validate_policy};
use pgroles_core::explorer::{AnalyzeRequest, analyze};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let operation = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("usage: analyze_fixture <analyze|validate|compile> <request.json>")?;
    let fixture = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: analyze_fixture <analyze|validate|compile> <request.json>")?;
    let input = std::fs::read_to_string(fixture)?;
    match operation.as_str() {
        "analyze" => {
            let request: AnalyzeRequest = serde_json::from_str(&input)?;
            println!("{}", serde_json::to_string(&analyze(request)?)?);
        }
        "validate" => {
            let request: PolicyRequest = serde_json::from_str(&input)?;
            println!("{}", serde_json::to_string(&validate_policy(request))?);
        }
        "compile" => {
            let request: PolicyRequest = serde_json::from_str(&input)?;
            println!("{}", serde_json::to_string(&compile_policy(request))?);
        }
        _ => return Err(format!("unknown operation: {operation}").into()),
    }
    Ok(())
}
