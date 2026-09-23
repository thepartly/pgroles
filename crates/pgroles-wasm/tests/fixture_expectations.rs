//! Native check that every analyze fixture means what its `expected` block
//! says. `wasm_parity.mjs` applies the same expectations to the WASM build.

use std::path::Path;

use pgroles_core::explorer::{AnalyzeRequest, analyze};
use serde_json::{Map, Value};

fn matches(actual: &Value, expected: &Value) -> bool {
    expected
        .as_object()
        .expect("expectation entries are objects")
        .iter()
        .all(|(key, value)| actual.get(key) == Some(value))
}

fn list<'a>(expected: &'a Map<String, Value>, key: &str) -> &'a [Value] {
    expected
        .get(key)
        .map(|value| {
            value
                .as_array()
                .expect("expectation lists are arrays")
                .as_slice()
        })
        .unwrap_or_default()
}

fn check(name: &str, response: &Value, expected: &Map<String, Value>) {
    let changes: Vec<Value> = response["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| {
            let (kind, details) = change.as_object().unwrap().iter().next().unwrap();
            let mut flattened = details.as_object().unwrap().clone();
            flattened.insert("kind".into(), Value::String(kind.clone()));
            Value::Object(flattened)
        })
        .collect();
    let findings = response["findings"].as_array().unwrap();
    for change in list(expected, "changes") {
        assert!(
            changes.iter().any(|actual| matches(actual, change)),
            "{name}: missing change {change} in {changes:?}"
        );
    }
    for kind in list(expected, "absentChanges") {
        assert!(
            !changes.iter().any(|change| &change["kind"] == kind),
            "{name}: unexpected {kind}"
        );
    }
    for finding in list(expected, "findings") {
        assert!(
            findings.iter().any(|actual| matches(actual, finding)),
            "{name}: missing finding {finding} in {findings:#?}"
        );
    }
    for finding in list(expected, "absentFindings") {
        assert!(
            !findings.iter().any(|actual| matches(actual, finding)),
            "{name}: unexpected finding {finding} in {findings:#?}"
        );
    }
    for boundary in list(expected, "phaseReachability") {
        let candidates: Vec<_> = response["phases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|phase| phase["phase"] == boundary["phase"])
            .collect();
        let phase = match boundary.get("occurrence") {
            Some(occurrence) => candidates[occurrence.as_u64().unwrap() as usize],
            None => {
                assert_eq!(candidates.len(), 1, "{name}: ambiguous {boundary}");
                candidates[0]
            }
        };
        let statuses = match boundary["authority"].as_str().unwrap() {
            "usage" => &phase["executor_usage"],
            "set_role" => &phase["executor_reachability"],
            other => panic!("{name}: invalid authority {other}"),
        };
        let status = statuses
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["role"] == boundary["role"])
            .map(|item| &item["status"]);
        assert_eq!(status, Some(&boundary["status"]), "{name}: {boundary}");
    }
    if let Some(fields) = expected.get("response") {
        for (field, value) in fields.as_object().unwrap() {
            assert_eq!(&response[field], value, "{name}: response {field}");
        }
    }
}

#[test]
fn analyze_fixtures_match_their_expectations() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut names: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    assert!(!names.is_empty());
    for name in names {
        let fixture: Value =
            serde_json::from_str(&std::fs::read_to_string(directory.join(&name)).unwrap())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        let request: AnalyzeRequest = serde_json::from_value(fixture["request"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let expected = fixture["expected"]
            .as_object()
            .unwrap_or_else(|| panic!("{name}: missing expected"));
        assert!(
            fixture["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{name}: missing description"
        );
        let response = serde_json::to_value(analyze(request).unwrap()).unwrap();
        check(&name, &response, expected);
    }
}
