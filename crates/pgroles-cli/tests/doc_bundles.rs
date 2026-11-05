//! Compose every policy bundle shown in the documentation.
//!
//! A bundle example spans several fenced blocks — the root file and one block
//! per fragment — so no single block is checkable on its own. Blocks name the
//! file they stand for in a leading `# <file>.yaml` comment; this test writes
//! each page's named blocks into a scratch directory and composes every root
//! bundle (a block with top-level `sources:`) exactly as `pgroles validate
//! --bundle` would.
//!
//! The documented bundle examples once failed composition for months because
//! nothing exercised them; this is what keeps that from happening again.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Blocks containing this marker are deliberate templates, not files.
const ELISION_MARKER: &str = "# ...";

/// Trees that ship copy-pasteable examples, relative to the repository root.
const MARKDOWN_ROOTS: [&str; 2] = ["docs/src/pages", "skills"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should exist relative to the crate")
}

fn markdown_pages() -> Vec<PathBuf> {
    let root = repo_root();
    let mut pages = Vec::new();
    let mut queue: Vec<PathBuf> = MARKDOWN_ROOTS.iter().map(|dir| root.join(dir)).collect();

    while let Some(dir) = queue.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("{} should be readable: {err}", dir.display()));
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                pages.push(path);
            }
        }
    }

    pages.sort();
    pages
}

/// YAML blocks whose first line names a file, as `(file, body)`.
fn named_yaml_blocks(markdown: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;

    for line in markdown.lines() {
        match current {
            None => {
                let fence = line.trim_start();
                if fence.starts_with("```yaml") || fence.starts_with("```yml") {
                    current = Some(String::new());
                }
            }
            Some(ref mut body) => {
                if !line.trim_start().starts_with("```") {
                    body.push_str(line);
                    body.push('\n');
                    continue;
                }
                let body = current.take().expect("block is open");
                if body.contains(ELISION_MARKER) {
                    continue;
                }
                let Some(file) = body
                    .lines()
                    .next()
                    .and_then(|first| first.strip_prefix("# "))
                    .map(str::trim)
                    .filter(|name| {
                        !name.contains('/') && (name.ends_with(".yaml") || name.ends_with(".yml"))
                    })
                else {
                    continue;
                };
                blocks.push((file.to_string(), body));
            }
        }
    }
    blocks
}

fn is_bundle_root(body: &str) -> bool {
    body.lines().any(|line| line.starts_with("sources:"))
}

#[test]
fn documented_bundles_compose() {
    let root = repo_root();
    let mut checked = 0usize;
    let mut failures = Vec::new();

    for page in markdown_pages() {
        let name = page
            .strip_prefix(&root)
            .unwrap_or(&page)
            .display()
            .to_string();
        let markdown = std::fs::read_to_string(&page).expect("page should be readable");
        let blocks = named_yaml_blocks(&markdown);
        if !blocks.iter().any(|(_, body)| is_bundle_root(body)) {
            continue;
        }

        // A page that shows two different files under one name is ambiguous
        // to a reader too, so flag it rather than guess which one composes.
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        for (file, body) in &blocks {
            if let Some(previous) = files.insert(file.clone(), body.clone())
                && previous != *body
            {
                failures.push(format!("{name}: two different blocks are named {file}"));
            }
        }

        let dir = tempfile::tempdir().expect("scratch directory");
        for (file, body) in &files {
            std::fs::write(dir.path().join(file), body).expect("write documented file");
        }

        for (file, body) in &files {
            if !is_bundle_root(body) {
                continue;
            }
            checked += 1;
            if let Err(error) = pgroles_cli::validate_bundle_file(&dir.path().join(file)) {
                failures.push(format!("{name}: {file}: {error:#}"));
            }
        }
    }

    assert!(
        checked > 0,
        "no documented bundles found — the extractor is probably broken"
    );
    assert!(
        failures.is_empty(),
        "documented bundles do not compose:\n  {}",
        failures.join("\n  ")
    );
}

mod regressions {
    use super::*;

    #[test]
    fn named_blocks_are_extracted_and_templates_skipped() {
        let markdown = "```yaml\n# bundle.yaml\nsources: []\n```\n\n\
                        ```yaml\n# app.yaml\nroles:\n  # ...\n```\n\n\
                        ```yaml\nroles: []\n```\n";
        let blocks = named_yaml_blocks(markdown);
        assert_eq!(
            blocks.len(),
            1,
            "only the named, complete block: {blocks:?}"
        );
        assert_eq!(blocks[0].0, "bundle.yaml");
        assert!(is_bundle_root(&blocks[0].1));
    }

    #[test]
    fn a_fragment_outside_its_scope_fails_composition() {
        let dir = tempfile::tempdir().expect("scratch directory");
        std::fs::write(
            dir.path().join("bundle.yaml"),
            "sources:\n  - file: app.yaml\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("app.yaml"),
            "policy:\n  name: app\nscope:\n  roles: []\nroles:\n  - name: stray\n",
        )
        .unwrap();
        assert!(pgroles_cli::validate_bundle_file(&dir.path().join("bundle.yaml")).is_err());
    }
}
