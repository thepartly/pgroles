use std::path::PathBuf;

use pgroles_core::explorer::{AnalyzeRequest, analyze};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: analyze_fixture <request.json>")?;
    let input = std::fs::read_to_string(fixture)?;
    let request: AnalyzeRequest = serde_json::from_str(&input)?;
    let response = analyze(request)?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}
